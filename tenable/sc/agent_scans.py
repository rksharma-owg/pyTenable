"""
Agent Scans
===========

The following methods allow for interaction with the Tenable Security Center
:sc-api:`Agent Scan <Agent-Scan.htm>` API.

Methods available on ``sc.agent_scans``:

.. rst-class:: hide-signature
.. autoclass:: AgentScanAPI
    :members:
"""

from tenable.errors import UnexpectedValueError

from .base import SCEndpoint


class AgentScanAPI(SCEndpoint):
    """The interface for the Tenable Security Center Agent Scan API."""

    def _schedule_constructor(self, schedule):
        self._check('schedule', schedule, dict)
        schedule['type'] = self._check(
            'schedule:type',
            schedule.get('type'),
            str,
            choices=['ical', 'never', 'rollover', 'triggered', 'template'],
            default='template',
        )
        if schedule['type'] == 'ical':
            self._check('schedule:start', schedule.get('start'), str)
            self._check('schedule:repeatRule', schedule.get('repeatRule'), str)
        return schedule

    def _constructor(self, **kw):
        if 'name' in kw:
            self._check('name', kw['name'], str)

        if 'type' in kw:
            self._check('type', kw['type'], str, choices=['plugin', 'policy'])

        if 'description' in kw:
            self._check('description', kw['description'], str)

        if 'manager_id' in kw:
            kw['nessusManager'] = {
                'id': self._check('manager_id', kw.pop('manager_id'), int)
            }

        if 'repo' in kw:
            kw['repository'] = {'id': self._check('repo', kw.pop('repo'), int)}

        if 'agent_group_ids' in kw:
            kw['agentGroups'] = [
                {'id': self._check('agent_group:id', item, int)}
                for item in self._check(
                    'agent_group_ids', kw.pop('agent_group_ids'), list
                )
            ]

        if 'policy_id' in kw:
            kw['policy'] = {'id': self._check('policy_id', kw.pop('policy_id'), int)}
            kw['type'] = 'policy'

        if 'scan_window' in kw:
            kw['scanWindow'] = str(
                self._check('scan_window', kw.pop('scan_window'), int)
            )

        if 'triggered_scan_interval' in kw:
            interval = self._check(
                'triggered_scan_interval',
                kw.pop('triggered_scan_interval'),
                int,
            )
            if interval != -1 and not 12 <= interval <= 1000:
                raise UnexpectedValueError(
                    'triggered_scan_interval must be -1 or between 12 and 1000'
                )
            kw['triggeredScanInterval'] = interval

        if 'triggered_scan_filename' in kw:
            kw['triggeredScanFilename'] = self._check(
                'triggered_scan_filename',
                kw.pop('triggered_scan_filename'),
                str,
            )

        if 'schedule' in kw:
            kw['schedule'] = self._schedule_constructor(kw['schedule'])

        if 'reports' in kw:
            for report in self._check('reports', kw['reports'], list):
                self._check('report:id', report['id'], int)
                self._check(
                    'report:reportSource',
                    report['reportSource'],
                    str,
                    choices=['cumulative', 'individual'],
                )

        return kw

    def list(self, fields=None):
        """
        Retrieves the list of Agent Scan definitions.

        :sc-api:`agent-scan: list <Agent-Scan.htm#agentScan_GET>`

        Args:
            fields (list, optional):
                A list of attributes to return for each Agent Scan.

        Returns:
            :obj:`dict`:
                The usable and manageable Agent Scan definitions.
        """
        params = {}
        if fields:
            params['fields'] = ','.join(
                [self._check('field', field, str) for field in fields]
            )
        return self._api.get('agentScan', params=params).json()['response']

    def create(self, name, manager_id, repo, **kw):
        """
        Creates an Agent Scan definition.

        :sc-api:`agent-scan: create <Agent-Scan.htm#agentScan_POST>`

        Args:
            name (str): The name of the Agent Scan.
            manager_id (int): The Nessus Manager identifier.
            repo (int): The repository identifier.
            agent_group_ids (list, optional):
                Agent group identifiers to include in the scan.
            description (str, optional): A description of the Agent Scan.
            policy_id (int, optional): The scan policy identifier.
            reports (list, optional):
                Report definitions to run after the scan.
            scan_window (int, optional): The scan window value.
            schedule (dict, optional): The Agent Scan schedule.
            triggered_scan_filename (str, optional):
                The filename used for a triggered scan.
            triggered_scan_interval (int, optional):
                The triggered scan interval.
            type (str, optional):
                Either ``plugin`` or ``policy``. Required unless
                ``policy_id`` is provided.

        Returns:
            :obj:`dict`:
                The newly created Agent Scan definition.

        Examples:
            >>> scan = sc.agent_scans.create(
            ...     'Weekly agents',
            ...     manager_id=1,
            ...     repo=2,
            ...     agent_group_ids=[3],
            ...     policy_id=1000001,
            ... )
        """
        kw['name'] = name
        kw['manager_id'] = manager_id
        kw['repo'] = repo
        payload = self._constructor(**kw)
        if payload.get('type') is None:
            raise UnexpectedValueError(
                'type is required when policy_id is not provided'
            )
        return self._api.post('agentScan', json=payload).json()['response']

    def details(self, id, fields=None):
        """
        Returns the details for an Agent Scan definition.

        :sc-api:`agent-scan: details <Agent-Scan.htm#agentScan_id_GET>`

        Args:
            id (int): The Agent Scan identifier.
            fields (list, optional): A list of attributes to return.

        Returns:
            :obj:`dict`:
                The Agent Scan definition.
        """
        params = {}
        if fields:
            params['fields'] = ','.join(
                [self._check('field', field, str) for field in fields]
            )
        return self._api.get(
            'agentScan/{}'.format(self._check('id', id, int)), params=params
        ).json()['response']

    def edit(self, id, **kw):
        """
        Edits an Agent Scan definition.

        :sc-api:`agent-scan: edit <Agent-Scan.htm#agentScan_id_PATCH>`

        Args:
            id (int): The Agent Scan identifier.
            agent_group_ids (list, optional):
                Agent group identifiers to include in the scan.
            description (str, optional): A description of the Agent Scan.
            manager_id (int, optional): The Nessus Manager identifier.
            name (str, optional): The name of the Agent Scan.
            policy_id (int, optional): The scan policy identifier.
            repo (int, optional): The repository identifier.
            reports (list, optional):
                Report definitions to run after the scan.
            scan_window (int, optional): The scan window value.
            schedule (dict, optional): The Agent Scan schedule.
            triggered_scan_filename (str, optional):
                The filename used for a triggered scan.
            triggered_scan_interval (int, optional):
                The triggered scan interval.
            type (str, optional): Either ``plugin`` or ``policy``.

        Returns:
            :obj:`dict`:
                The updated Agent Scan definition.
        """
        payload = self._constructor(**kw)
        return self._api.patch(
            'agentScan/{}'.format(self._check('id', id, int)), json=payload
        ).json()['response']

    def delete(self, id):
        """
        Deletes an Agent Scan definition.

        :sc-api:`agent-scan: delete <Agent-Scan.htm#agentScan_id_DELETE>`

        Args:
            id (int): The Agent Scan identifier.

        Returns:
            :obj:`str`:
                An empty response.
        """
        return self._api.delete(
            'agentScan/{}'.format(self._check('id', id, int))
        ).json()['response']

    def launch(self, id):
        """
        Launches an Agent Scan definition.

        :sc-api:`agent-scan: launch <Agent-Scan.htm#agentScan_id_launch_POST>`

        Args:
            id (int): The Agent Scan identifier.

        Returns:
            :obj:`dict`:
                The queued Agent Scan result.
        """
        return self._api.post(
            'agentScan/{}/launch'.format(self._check('id', id, int)), json={}
        ).json()['response']
