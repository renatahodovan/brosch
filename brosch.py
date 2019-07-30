#!/usr/bin/env python3

# Copyright (c) 2019 Renata Hodovan, Akos Kiss.
#
# Licensed under the BSD 3-Clause License
# <LICENSE.rst or https://opensource.org/licenses/BSD-3-Clause>.
# This file may not be copied, modified, or distributed except
# according to those terms.

import bugzilla
import git
import glob
import json
import os
import re
import time

from argparse import ArgumentParser
from datetime import datetime, timezone
from ruamel.yaml import YAML

__version__ = '19.7'


# Utility functions

def str_to_datetime(date_string):
    """
    Convert a string in ``YYYY-MM-DD [HH[:MM[:SS]]]`` format to a datetime
    object.
    """
    try:
        return datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.strptime(date_string, '%Y-%m-%d %H:%M').replace(tzinfo=timezone.utc)
        except ValueError:
            try:
                return datetime.strptime(date_string, '%Y-%m-%d %H').replace(tzinfo=timezone.utc)
            except ValueError:
                return datetime.strptime(date_string, '%Y-%m-%d').replace(tzinfo=timezone.utc)


def json_dump(data, file):
    """
    Dump a data structure to a file in JSON format.
    """
    json.dump(data, file, indent=2, sort_keys=True)


def yaml_dump(data, file):
    """
    Dump a data structure to a file in YAML format.
    Strings containing line breaks are emitted in literal block scalar style.
    """
    yaml = YAML(typ='safe', pure=True)
    yaml.default_flow_style = False
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.allow_unicode = True
    yaml.representer.add_representer(str, lambda dumper, data: dumper.represent_scalar(u'tag:yaml.org,2002:str', data, style='|' if '\n' in data else None))
    yaml.dump(data, file)


dumpers = {
    'json': json_dump,
    'yaml': yaml_dump,
}


# Security commit history miners

class GitBzMiner(object):
    """
    Generic Git+Bugzilla-based security commit history miner.
    """

    @classmethod
    def collect(cls, work_dir, repo_dir, after_date=None, before_date=None):
        """
        Step 1: Collect unique issue IDs referenced in commit messages.
        """
        print('Collect issue IDs from {engine} git log'.format(engine=cls.name))

        issue_ids = set()

        commit_count = 0
        first_date = last_date = None

        repo = git.Repo(repo_dir)
        for commit in repo.iter_commits('master'):
            if (before_date and commit.committed_datetime >= before_date) or (after_date and commit.committed_datetime <= after_date):
                continue

            issue_ids.update(int(id) for id in cls.issue_id_pattern.findall(commit.message))

            commit_count += 1
            first_date = commit.committed_datetime if not first_date else min(first_date, commit.committed_datetime)
            last_date = commit.committed_datetime if not last_date else max(last_date, commit.committed_datetime)

        issue_ids.difference_update(cls.incorrect_issue_ids)

        print('\tProcessed {cnt} commits between {first} and {last}'.format(cnt=commit_count, first=first_date, last=last_date))
        print('\tFound {cnt} unique issue IDs'.format(cnt=len(issue_ids)))

        os.makedirs(work_dir, exist_ok=True)
        with open(os.path.join(work_dir, '{engine}_issue_ids.json'.format(engine=cls.name)), 'w') as f:
            json_dump(sorted(issue_ids), f)

    @classmethod
    def identify(cls, work_dir, from_id=None, to_id=None, chunk_size=1000, sleep_time=30, retry=0):
        """
        Step 2: Identify security issue IDs by querying issue tracker.
        """
        print('Load collected issue IDs')
        with open(os.path.join(work_dir, '{engine}_issue_ids.json'.format(engine=cls.name)), 'r') as f:
            issue_ids = json.load(f)
            print('\tFound {cnt} issue IDs in range from {first} to {last}'.format(cnt=len(issue_ids), first=issue_ids[0], last=issue_ids[-1]))

        if from_id is not None or to_id is not None:
            if from_id is not None:
                issue_ids = [id for id in issue_ids if id >= from_id]
            if to_id is not None:
                issue_ids = [id for id in issue_ids if id <= to_id]
            print('\tBounded list has {cnt} issue IDs in range from {first} to {last}'.format(cnt=len(issue_ids), first=issue_ids[0], last=issue_ids[-1]))

        bzapi = bugzilla.Bugzilla(cls.bugzilla_url)
        if os.path.exists(bzapi.tokenfile):
            os.remove(bzapi.tokenfile)
        if os.path.exists(bzapi.cookiefile):
            os.remove(bzapi.cookiefile)

        for from_idx in range(0, len(issue_ids), chunk_size):
            sec_issues = dict()
            pub_count = priv_count = 0

            chunk_ids = issue_ids[from_idx : from_idx + chunk_size]
            print('Query {cnt} issue IDs in range from {first} to {last}'.format(cnt=len(chunk_ids), first=chunk_ids[0], last=chunk_ids[-1]))

            for tr in range(retry + 1):
                try:
                    issues = bzapi._proxy.Bug.get({ 'ids': chunk_ids, 'permissive': 1 })
                    break
                except Exception as e:
                    print('\tException occured during query: {e}'.format(e=e))
                    if tr >= retry:
                        raise
                    print('\tRetry after {time} seconds'.format(time=sleep_time * 2))
                    time.sleep(sleep_time * 2)

            for issue in issues['faults']:
                if issue['faultCode'] == 102:
                    sec_issues[issue['id']] = 'private'
                    priv_count += 1

            for issue in issues['bugs']:
                if cls.public_issue(issue):
                    sec_issues[issue['id']] = 'public'
                    pub_count += 1

            print('\tIdentified {pub} public and {priv} private security issue IDs'.format(pub=pub_count, priv=priv_count))

            with open(os.path.join(work_dir, '{engine}_sec_issue_ids_{first}_{last}.json'.format(engine=cls.name, first=chunk_ids[0], last=chunk_ids[-1])), 'w') as f:
                json_dump(sec_issues, f)

            print('\tSleep for {time} seconds'.format(time=sleep_time))
            time.sleep(sleep_time)

    @classmethod
    def match(cls, work_dir, repo_dir, after_date=None, before_date=None, format='json', extended=False):
        """
        Step 3: Match security issue IDs to commits.
        """
        print('Load identified security issue IDs')
        sec_issues = dict()
        for fn in glob.glob(os.path.join(work_dir, '{engine}_sec_issue_ids_*.json'.format(engine=cls.name))):
            with open(fn, 'r') as f:
                sec_issues.update({int(id): vis for id, vis in json.load(f).items()})
        print('\tFound {cnt} security issues'.format(cnt=len(sec_issues)))

        print('Match security issue IDs to commits')
        sec_commits = []

        repo = git.Repo(repo_dir)
        for commit in repo.iter_commits('master'):
            if (before_date and commit.committed_datetime >= before_date) or (after_date and commit.committed_datetime <= after_date):
                continue

            commit_sec_issues = {int(id): sec_issues[int(id)] for id in cls.issue_id_pattern.findall(commit.message) if int(id) in sec_issues}
            if commit_sec_issues:
                sec_commit = {
                    'id': commit.hexsha,
                    'authored-date': str(commit.authored_datetime),
                    'committed-date': str(commit.committed_datetime),
                    'security-issue-ids': commit_sec_issues,
                }
                if extended:
                    sec_commit.update({
                        'author': { 'name': commit.author.name, 'email': commit.author.email },
                        'committer': { 'name': commit.committer.name, 'email': commit.committer.email },
                        'message': commit.message,
                    })
                sec_commits.append(sec_commit)

        metadata = {
            'project': cls.name,
            'repository': next(repo.remotes.origin.urls),
            'issue-tracker': cls.bugzilla_url,
            'generator': '{prog} {version}'.format(prog=os.path.splitext(os.path.basename(__file__))[0], version=__version__),
        }
        if before_date:
            metadata['committed-before'] = str(before_date)
        if after_date:
            metadata['committed-after'] = str(after_date)

        with open(os.path.join(work_dir, '{engine}_sec_commits.{format}'.format(engine=cls.name, format=format)), 'w') as f:
            dumpers[format]({
                'metadata': metadata,
                'commits': list(reversed(sec_commits))
            }, f)
        print('\tFound {cnt} security-related commits'.format(cnt=len(sec_commits)))


class FirefoxMiner(GitBzMiner):
    """
    Firefox security commit history miner.
    """

    name = 'firefox'
    issue_id_pattern = re.compile(r'(?:[Bb]ug #?|b=|\()([0-9]+)')
    incorrect_issue_ids = {
        191053, # NOTE: issue ID is valid but result returned by server kills XMLRPC client; manually verified, issue is not security-related
        7258114800,
        819187200000,
        140278833279472,
        140279013634496,
        140279059771888,
        140279059772464,
        140279059773088,
        140279059773280,
        140279059773712,
        140279059774384,
    }
    bugzilla_url = 'https://bugzilla.mozilla.org'

    @classmethod
    def public_issue(cls, issue):
        # return ('Core' in issue['product'] or 'Firefox' in issue['product']) and 'Security' in issue['component']
        return 'Security' in issue['component']


class WebkitMiner(GitBzMiner):
    """
    Webkit security commit history miner.
    """

    name = 'webkit'
    issue_id_pattern = re.compile(r'(?:https://bugs.webkit.org/show_bug.cgi\?id=|https://webkit.org/b/)([0-9]+)')
    incorrect_issue_ids = {
        522772,
        130249111,
        9475294867,
    }
    bugzilla_url = 'https://bugs.webkit.org'

    @classmethod
    def public_issue(cls, issue):
        return issue['product'] == 'Security'


# CLI

miners = {
    'firefox': FirefoxMiner,
    'webkit': WebkitMiner,
}


def collect_step(args):
    miners[args.browser].collect(work_dir=args.out, repo_dir=args.repo, after_date=args.after, before_date=args.before)


def identify_step(args):
    miners[args.browser].identify(work_dir=args.out, from_id=args.from_id, to_id=args.to_id, retry=args.retry)


def match_step(args):
    miners[args.browser].match(work_dir=args.out, repo_dir=args.repo, after_date=args.after, before_date=args.before, format=args.format, extended=args.extended)


if __name__ == '__main__':
    parser = ArgumentParser(description='BroSCH: Browser Security Commit History mining tool')
    parser.add_argument('-b', '--browser', metavar='NAME', choices=['firefox', 'webkit'], required=True,
                        help='browser engine to mine (%(choices)s)')
    parser.add_argument('-o', '--out', metavar='DIR', default=os.getcwd(),
                        help='output directory of the results (default: %(default)s)')
    parser.add_argument('--version', action='version', version='%(prog)s {version}'.format(version=__version__))
    subparsers = parser.add_subparsers(title='subcommands', metavar='CMD',
                                       help='mining steps')

    c_parser = subparsers.add_parser('collect',
                                     help='step 1: collect unique issue IDs referenced in commit messages')
    c_parser.add_argument('-r', '--repo', metavar='DIR', required=True,
                          help='directory of the browser engine\'s git repository')
    c_parser.add_argument('--before', metavar='DATETIME', type=str_to_datetime,
                          help='collect issue IDs only from commits committed before this date (format: YYYY-MM-DD [HH[:MM[:SS]]])')
    c_parser.add_argument('--after', metavar='DATETIME', type=str_to_datetime,
                          help='collect issue IDs only from commits committed after this date (format: YYYY-MM-DD [HH[:MM[:SS]]])')
    c_parser.set_defaults(step=collect_step)

    i_parser = subparsers.add_parser('identify',
                                     help='step 2: identify security issue IDs by querying issue tracker')
    i_parser.add_argument('--from', metavar='ID', type=int, dest='from_id',
                          help='lower bound of issue IDs to query (default: first issue ID collected from the git log)')
    i_parser.add_argument('--to', metavar='ID', type=int, dest='to_id',
                          help='upper bound of issue IDs to query (default: last issue ID collected from the git log)')
    i_parser.add_argument('--retry', metavar='N', type=int, default=0,
                          help='number of times to retry a failed issue tracker query (default: %(default)s)')
    i_parser.set_defaults(step=identify_step)

    m_parser = subparsers.add_parser('match',
                                     help='step 3: match security issue IDs to commits')
    m_parser.add_argument('-r', '--repo', metavar='DIR', required=True,
                          help='directory of the browser engine\'s git repository')
    m_parser.add_argument('--before', metavar='DATETIME', type=str_to_datetime,
                          help='match commits to security issue IDs only if committed before this date (format: YYYY-MM-DD [HH[:MM[:SS]]])')
    m_parser.add_argument('--after', metavar='DATETIME', type=str_to_datetime,
                          help='match commits to security issue IDs only if committed after this date (format: YYYY-MM-DD [HH[:MM[:SS]]])')
    m_parser.add_argument('--format', metavar='EXT', choices=['json', 'yaml'], default='json',
                          help='result format (%(choices)s; default: %(default)s)')
    m_parser.add_argument('--extended', action='store_true',
                          help='extend result with commit details (default: author and committer name, and commit message are not included in the result)')
    m_parser.set_defaults(step=match_step)

    args = parser.parse_args()
    if 'step' not in args:
        parser.error('a subcommand (i.e., a mining step) must be provided')

    args.step(args)
