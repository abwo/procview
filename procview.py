import argparse
from datetime import datetime
import hashlib
import os
import re
import subprocess


class WinProcViewer(object):
    def __init__(self):
        pass

    def _execute_cmd(self, cmd_line):
        result = subprocess.run(
            cmd_line,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        try:
            result = result.stdout.decode('cp932')
        except UnicodeDecodeError:
            raise
        return result

    def _get_gps_format_list(self):
        cmd_line = 'powershell Get-Process -pid 0 | Format-List *'
        result = self._execute_cmd(cmd_line)
        gps_format_list = []
        for line in result.splitlines():
            if ':' in line:
                key = line.split(':')[0].strip()
                gps_format_list.append(key)
        return gps_format_list

    def get_process_list(self):
        cmd_line = 'powershell get-process'
        result = self._execute_cmd(cmd_line)
        process_list = []
        for process in result.splitlines():
            process = process.split()
            process_id_name = ''
            if len(process) == 7:
                process_id_name = {
                    'id': process[4], 'name': process[6]}
            elif len(process) == 8:
                process_id_name = {
                    'id': process[5], 'name': process[7]}
            else:
                continue

            # for excepting get-process's result header
            try:
                int(process_id_name['id'])
            except ValueError:
                continue

            process_list.append(process_id_name)
        return process_list

    def get_process_detail_list(self):
        cmd_line = 'powershell Get-Process | Format-List *'
        result = self._execute_cmd(cmd_line)
        process_detail_list = []
        process_detail = {}
        # '^([^:]+)\s+:\s+(.*)$' -> 'key   : val'
        pattern = re.compile('^([^:]+)\s+:\s+(.*)$')
        for line in result.splitlines():

            match_obj = pattern.search(line)
            if match_obj:
                key = match_obj.group(1).strip()
                val = match_obj.group(2)
                process_detail[key] = val

            if not line and not process_detail:
                pass
            elif not line:
                process_detail_list.append(process_detail)
                process_detail = {}

        return process_detail_list

    def get_process_bin_list(self):
        cmd_line = (
            'powershell Get-Process | '
            'Sort-Object Path |Select-Object -ExpandProperty Path -Unique'
        )
        result = self._execute_cmd(cmd_line)
        bin_list = [line.strip() for line in result.splitlines()]
        return bin_list

    def _get_file_size(self, file_path):
        return os.path.getsize(file_path)

    def _get_hash_vals(self, bin_path):
        hash_vals = {}
        with open(bin_path, mode='rb') as bp:
            hash_vals['md5'] = hashlib.md5(bp.read()).hexdigest()
            hash_vals['sha1'] = hashlib.sha1(bp.read()).hexdigest()
            hash_vals['sha256'] = hashlib.sha256(bp.read()).hexdigest()
            hash_vals['sha512'] = hashlib.sha512(bp.read()).hexdigest()
        return hash_vals

    def _get_timestamp_vals(self, bin_path):
        timestamp_vals = {}
        timestamp_vals['ctime'] = os.path.getctime(bin_path)
        timestamp_vals['mtime'] = os.path.getmtime(bin_path)
        timestamp_vals['atime'] = os.path.getatime(bin_path)
        for timetype, timestamp in timestamp_vals.items():
            timestamp_vals[timetype] = (
                datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            )
        return timestamp_vals

    def _get_verified_signer(self, bin_path):
        cmd_line = (
            'powershell \"get-authenticodeSignature -filepath \'{bin_path}\''
            ' | format-list SignerCertificate,Status\"'
            .format(bin_path=bin_path)
        )
        result = self._execute_cmd(cmd_line)
        verified_signer = {}

        for line in result.splitlines():
            pattern_signer = r'CN=.*, O=([^,]+), .*$'
            match_signer = re.search(pattern_signer, line)
            if match_signer and 'signer' not in verified_signer:
                verified_signer['signer'] = match_signer.group(1)

            pattern_status = r'^Status\s+:\s+(\w+)$'
            match_status = re.search(pattern_status, line)
            if match_status:
                verified_signer['status'] = match_status.group(1)

        if 'signer' not in verified_signer:
            verified_signer['signer'] = None

        return verified_signer

    def get_process_bin_notes_list(self):
        process_bin_list = self.get_process_bin_list()
        process_bin_notes_list = []
        for bin_path in process_bin_list:
            process_bin_notes = {
                'path': bin_path,
                'size': self._get_file_size(bin_path),
                'hash_vals': self._get_hash_vals(bin_path),
                'timestamp_vals': self._get_timestamp_vals(bin_path),
                'verified_signer': self._get_verified_signer(bin_path),
            }
            process_bin_notes_list.append(process_bin_notes)
        return process_bin_notes_list

    def get_process_network(self):
        cmd_line = 'netstat -ano'
        result = self._execute_cmd(cmd_line)
        process_list = self.get_process_list()
        local_pattern = '[^:]+|\[.+\]'
        remote_pattern = local_pattern
        state_pattern = '\s+|\w+'
        pattern = re.compile(
            # (proto)  (localaddr):(port)  (remoteaddr):(port)  (state)  (pid)
            r'(\w+)\s+({local}):(\d+|\*)\s+({remote}):(\d+|\*)\s+({state})\s+(\d+)$'
            .format(
                local=local_pattern, remote=remote_pattern, state=state_pattern
            )
        )
        process_networks = []
        process_network = {}
        for line in result.splitlines():
            pid = ''
            pname = ''
            match_obj = pattern.search(line)
            if not match_obj:
                continue
            pid = match_obj.group(7)
            for process in process_list:
                if process['id'] == pid:
                    pname = process['name']
            process_network = {
                'name': pname,
                'pid': pid,
                'proto': match_obj.group(1),
                'local_addr': match_obj.group(2),
                'local_port': match_obj.group(3),
                'remote_addr': match_obj.group(4),
                'remote_port': match_obj.group(5),
                'state': match_obj.group(6)
            }
            process_networks.append(process_network)
        return process_networks

    def view_process_list(self):
        process_list = self.get_process_list()
        print('name, pid')
        print('----')
        for process in process_list:
            print('{0}, {1}' .format(process['name'], process['id']))

    def view_process_detail_list(self):
        process_detail_list = self.get_process_detail_list()
        print('----')
        for process_detail in process_detail_list:
            for key, val in process_detail.items():
                print('{key:30s}: {val}'.format(key=key, val=val))
            print('----\n')

    def view_process_bin_notes(self):
        bin_notes_list = self.get_process_bin_notes_list()
        for bin_notes in bin_notes_list:
            print('----')
            keys = [
                'path', 'size', 'hash_vals',
                'timestamp_vals', 'verified_signer'
            ]
            for key in keys:
                if (
                    key == 'hash_vals'
                    or key == 'timestamp_vals'
                    or key == 'verified_signer'
                ):
                    for subkey in bin_notes[key]:
                        print(
                            '{key:30s}: {val}'
                            .format(
                                key=key+'('+subkey+')',
                                val=bin_notes[key][subkey])
                        )
                else:
                    print(
                        '{key:30s}: {val}'.format(key=key, val=bin_notes[key])
                    )
            print('----\n')

    def view_process_network(self):
        process_networks = self.get_process_network()

        print(
            '{0:20}{1:10}{2:5}{3:^31}{4:^31}{5:10}'
            .format(
                'name', 'pid', 'proto', 'local', 'remote', 'state'
            )
        )
        print(
            '---------------------------------------------------------'
            '---------------------------------------------------------'
        )
        for pn in sorted(process_networks, key=lambda x: x['name']):
            print(
                '{0:20}{1:10}{2:5}{3:>20}:{4:10}{5:>20}:{6:10}{7:10}'
                .format(
                    pn['name'], pn['pid'], pn['proto'],
                    pn['local_addr'], pn['local_port'],
                    pn['remote_addr'], pn['remote_port'],
                    pn['state']
                )
            )


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--bin', action='store_true')
    parser.add_argument('--network', action='store_true')
    args = parser.parse_args()
    return args


def main():
    args = get_args()
    wpv = WinProcViewer()
    if args.verbose:
        wpv.view_process_detail_list()
    elif args.bin:
        wpv.view_process_bin_notes()
    elif args.network:
        wpv.view_process_network()
    else:
        wpv.view_process_list()


if __name__ == '__main__':
    main()
