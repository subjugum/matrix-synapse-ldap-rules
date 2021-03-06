# -*- coding: utf-8 -*-
# Copyright 2022 Johannes H.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import ssl
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import ldap3
import ldap3.core.exceptions
import synapse
from pkg_resources import parse_version
from synapse.api.errors import SynapseError, ShadowBanError
from synapse.module_api import ModuleApi
from twisted.internet import threads

__version__ = "0.0.2"

logger = logging.getLogger(__name__)


@dataclass
class _Config:
    enabled: bool
    uri: Union[str, List[str]]
    start_tls: bool
    bind_dn: str
    bind_password: str
    inviter: str
    room_mapping: Dict[str, Dict[str, Any]]
    filter: str


class LdapRules:
    _ldap_tls = ldap3.Tls(validate=ssl.CERT_REQUIRED)

    def __init__(self, config: _Config, api: ModuleApi):
        self.api_handler: ModuleApi = api
        synapse_min_version = "1.46.0"  # Introduces ModuleApi.update_room_membership

        if parse_version(synapse.__version__) < parse_version(synapse_min_version):
            raise Exception(
                "Running Synapse version %s, %s required."
                .format(synapse.__version__, synapse_min_version)
            )

        self.ldap_uris = [config.uri] if isinstance(
            config.uri, str) else config.uri
        self.ldap_start_tls = config.start_tls
        self.ldap_bind_dn = config.bind_dn
        self.ldap_bind_password = config.bind_password
        self.ldap_filter = config.filter
        self.inviter = config.inviter
        self.room_mapping = config.room_mapping

        # module-callback for Synapse
        api.register_account_validity_callbacks(
            on_user_registration=self.on_register
        )

    @staticmethod
    def parse_config(config) -> _Config:
        # verify config sanity
        _require_keys(
            config,
            [
                "uri",
                "bind_dn",
                "bind_password",
                "filter",
                "inviter",
                "room_mapping",
            ],
        )

        ldap_config = _Config(
            enabled=config.get("enabled", False),
            uri=config["uri"],
            start_tls=config.get("start_tls", False),
            bind_dn=config["bind_dn"],
            bind_password=config["bind_password"],
            filter=config["filter"],
            inviter=config["inviter"],
            room_mapping=config["room_mapping"],
        )

        # Make invite key optional
        for group, mapping in ldap_config.room_mapping.items():
            if "invite" not in ldap_config.room_mapping[group]:
                # TODO: Check this per room, not per group?
                mapping["invite"] = False

        return ldap_config

    def _get_server(self, get_info: Optional[str] = None) -> ldap3.ServerPool:
        """Constructs ServerPool from configured LDAP URIs

        Args:
            get_info: specifies if the server schema and server
            specific info must be read. Defaults to None.

        Returns:
            Servers grouped in a ServerPool
        """
        return ldap3.ServerPool(
            [
                ldap3.Server(uri, get_info=get_info, tls=self._ldap_tls)
                for uri in self.ldap_uris
            ],
        )

    async def _ldap_simple_bind(
        self, server: ldap3.ServerPool, bind_dn: str, password: str
    ) -> Tuple[bool, Optional[ldap3.Connection]]:
        """Attempt a simple bind with the credentials given against
        the LDAP server.

        Returns True, LDAP3Connection
            if the bind was successful
        Returns False, None
            if an error occured
        """

        try:
            conn = await threads.deferToThread(
                ldap3.Connection,
                server,
                bind_dn,
                password,
                authentication=ldap3.SIMPLE,
                read_only=True,
            )
            logger.debug(
                "Established LDAP connection in simple bind mode: %s", conn)

            if self.ldap_start_tls:
                await threads.deferToThread(conn.open)
                await threads.deferToThread(conn.start_tls)
                logger.debug(
                    "Upgraded LDAP connection in simple bind mode through "
                    "StartTLS: %s",
                    conn,
                )

            if await threads.deferToThread(conn.bind):
                # GOOD: bind okay
                logger.debug("LDAP Bind successful in simple bind mode.")
                return (True, conn)

            # BAD: bind failed
            logger.info(
                "Binding against LDAP failed for '%s' failed: %s",
                bind_dn,
                conn.result["description"],
            )
            await threads.deferToThread(conn.unbind)
            return (False, None)

        except ldap3.core.exceptions.LDAPException as e:
            logger.warning("Error during LDAP authentication: %s", e)
            raise

    async def _check_membership(
        self, conn: ldap3.Connection, username: str, ldap_group: str, ldap_base: str
    ) -> bool:
        """Checks whether a group contains a user. This could technically be
        any property of the group. We provide group properties that resolve to
        users, because OpenLDAP does not support LDAP_MATCHING_RULE_IN_CHAIN.
        You will most likely have to modify this for your installation.

        Args:
            conn: LDAP connection object
            username: The users login.
            ldap_group: LDAP group to check for username.
            ldap_base: LDAP base of group

        Returns True
            if username was found in group
        Returns False
            if username was not found in group
        """
        query = self.ldap_filter.format(
            username=username,
            group=ldap_group
        )

        await threads.deferToThread(
            conn.search,
            search_base=ldap_base,
            search_filter=query,
        )

        responses = [
            response
            for response in conn.response
            if response["type"] == "searchResEntry"
        ]

        if len(responses) == 1:
            # GOOD: found exactly one result
            logger.info(
                "LDAP search found match for user '%s' in group '%s'", username, ldap_group)
            return True
        else:
            # BAD: found 0 or >1 results, complain loudly to your LDAP admin in case of the latter
            if len(responses) == 0:
                logger.info(
                    "LDAP search returned no results for '%s' in group '%s'", username, ldap_group)
            else:
                logger.info(
                    "LDAP search returned too many (%s) results for '%s'",
                    len(responses),
                    query,
                )
            return False

    async def _join_to_room(
        self, sender: str, target: str, roomid: str, invite: Optional[bool] = False
    ) -> bool:
        """Tries to force-join a user into a room.

        Args:
            sender: Inviters mxid, must be local
            target: Invitees mxid, must be local
            roomid: The roomid to join
            invite: If True, only invite

        Returns True
            if join or invite was successful
        Returns False
            if join or invite failed
        """
        joined = False

        try:
            # https://spec.matrix.org/v1.2/client-server-api/#room-membership
            await self.api_handler.update_room_membership(
                sender,
                target,
                roomid,
                "invite"
            )
            # Only the user themself can join a room
            if not invite:
                await self.api_handler.update_room_membership(
                    target,
                    target,
                    roomid,
                    "join"
                )
            joined = True
        except RuntimeError as e:
            logger.info("Inviter '%s' not a local user?\n%s", sender, e)
        except ShadowBanError:
            logger.info("Inviter '%s' is shadowbanned", sender)
        except SynapseError as e:
            logger.exception(
                "Error occured when trying to join '%s' into '%s': %s",
                target,
                roomid,
                e
            )

        if joined:
            logger.info("Joined user '%s' into room '%s'", target, roomid)
        return joined

    async def on_register(self, username: str):
        server = self._get_server()
        result, conn = await self._ldap_simple_bind(
            server=server,
            bind_dn=self.ldap_bind_dn,
            password=self.ldap_bind_password,
        )
        # Connection failed, bind function should throw an exception regardless
        if not result:
            logging.warning("LDAP bind failed, can't process user '%s'", username)
            return

        # username from callback will be fully qualified
        localpart = username.split(":", 1)[0][1:]
        logging.debug("'%s' just got registered, localpart '%s'",
                      username, localpart)

        for group, mapping in self.room_mapping.items():
            base = mapping["base"]
            invite = mapping["invite"]
            roomids = mapping["roomids"]

            logging.debug(
                "Entering room_mapping for group '%s', base '%s' and "
                "check whether '%s' exists in group",
                group,
                base,
                localpart,
            )
            # Check whether user is in group ...
            if await self._check_membership(conn, localpart, group, base):
                logging.debug(
                    "User '%s' found in group '%s', rooms to join: %s",
                    localpart,
                    group,
                    roomids,
                )

                # ... on success we can iterate through rooms to join
                for roomid in roomids:
                    # Finally join or invite user to room
                    await self._join_to_room(self.inviter, username, roomid, invite)
        # Destroy LDAP connection after we're done
        await threads.deferToThread(conn.unbind)


def _require_keys(config: Dict[str, Any], required: Iterable[str]) -> None:
    missing = [key for key in required if key not in config]
    if missing:
        raise Exception(
            "Module enabled but missing required config values: {}".format(
                ", ".join(missing),
            )
        )
