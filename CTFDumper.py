#!/usr/bin/env python3
from argparse import ArgumentParser
from jinja2 import Template
from aiohttp import ClientSession
from urllib.parse import urljoin, urlparse, urlsplit
from typing import AsyncIterable
import logging
import logging.config
import os
import re
import aiofiles
import aiofiles.os
from asyncio import run, gather


banner = r"""
  ____ _____ _____ ____
 / ___|_   _|  ___|  _ \ _   _ _ __ ___  _ __   ___ _ __
| |     | | | |_  | | | | | | | '_ ` _ \| '_ \ / _ \ '__|
| |___  | | |  _| | |_| | |_| | | | | | | |_) |  __/ |
 \____| |_| |_|   |____/ \__,_|_| |_| |_| .__/ \___|_|
                                        |_|
"""


CONFIG = {
    'username': None,
    'password': None,
    'nonce_regex': 'name="nonce"(?:[^<>]+)?value="([0-9a-f]{64})"',
    'base_url': None,
    'no_files': None,
    'no_resolve_urls': None,
    'no_login': None,
    'no_logo': None,
    'template': os.path.join(
        os.path.dirname(os.path.realpath(__file__)), 'templates/default.md'
    ),
    'verbose': logging.INFO,
    'blacklist': r'[^a-zA-Z0-9_\-\. ]'
}


logging.config.dictConfig(
    {
        'version': 1,
        'disable_existing_loggers': True
    }
)


logger = logging.getLogger(__name__)
url_pattern = re.compile(r'((https?):((\/\/)|(\\\\))+[\w\d:#@%\/;$~_?\+-=\\\.&]*)')


def welcome() -> None:
    if not CONFIG['no_logo']:
        print(banner)


async def setup() -> None:
    parser = ArgumentParser(description='A tool for dumping CTFd challenges')

    parser.add_argument(
        'url',
        help='Platform URL'
    )

    parser.add_argument(
        '-u',
        '--username',
        help='Platfrom username'
    )

    parser.add_argument(
        '-p',
        '--password',
        help='Platform password'
    )

    parser.add_argument(
        '--nonce-regex',
        help='Platform nonce regex'
    )

    parser.add_argument(
        '--auth-file',
        help='File containing username and password, seperated by newline'
    )

    parser.add_argument(
        '-n',
        '--no-login',
        help='Use this option if the platform does not require authentication',
        action='store_true'
    )

    parser.add_argument(
        '--no-logo',
        help='Do not print logo on startup',
        action='store_true'
    )

    parser.add_argument(
        '--no-files',
        help='Do not download files',
        action='store_true'
    )

    parser.add_argument(
        '--no-resolve-urls',
        help='Do not download resources from embedded urls in description',
        action='store_true'
    )

    parser.add_argument(
        '--trust-all',
        help='Will make directory as the name of the challenge, the slashes(/) character will automatically be replaced with underscores(_)',
        action='store_true'
    )

    parser.add_argument(
        '-t',
        '--template',
        help='Custom template path'
    )

    parser.add_argument(
        '-v',
        '--verbose',
        help='Verbose',
        action='store_true'
    )

    args = parser.parse_args()

    CONFIG['base_url'] = args.url
    CONFIG['no_files'] = args.no_files
    CONFIG['no_resolve_urls'] = args.no_resolve_urls
    CONFIG['no_login'] = args.no_login
    CONFIG['no_logo'] = args.no_logo

    if not args.no_login:
        CONFIG['username'] = args.username
        CONFIG['password'] = args.password

    if args.nonce_regex:
        CONFIG['nonce_regex'] = args.nonce_regex

    if args.auth_file:
        async with aiofiles.open(args.auth_file, 'r') as file:
            CONFIG['username'] = (await file.readline()).strip()
            CONFIG['password'] = (await file.readline()).strip()

    if args.trust_all:
        CONFIG['blacklist'] = '/'

    if args.verbose:
        CONFIG['verbose'] = logging.DEBUG

    if args.template:
        CONFIG['template'] = args.template

    logging.basicConfig(
        level=CONFIG['verbose'],
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    logging.addLevelName(logging.ERROR, '[-]')
    logging.addLevelName(logging.INFO, '[+]')
    logging.addLevelName(logging.DEBUG, '[*]')


async def get_nonce() -> str | None:
    response = await session.get(urljoin(CONFIG['base_url'], '/login'))
    match = re.search(CONFIG['nonce_regex'], await response.text())

    return match[1] if match else None


async def login() -> None:
    nonce = await get_nonce()
    logger.debug(f'Nonce: {nonce}')

    response = await session.post(
        urljoin(CONFIG['base_url'], '/login'),
        data={
            'name': CONFIG['username'],
            'password': CONFIG['password'],
            'nonce': nonce
        }
    )

    if 'incorrect' in await response.text():
        logger.error('Login failed!')
        exit(1)


async def logout() -> None:
    await session.get(urljoin(CONFIG['base_url'], '/logout'))
    logger.info('Done! Logging you out!')


async def fetch(url: str) -> list[dict[str, str]] | dict[str, str] | None:
    logger.debug(f'Fetching {url}')

    response = await session.get(url)
    json = await response.json()

    return json['data'] if response.ok and json['success'] else None


async def fetch_file(filepath: str, filename: str, clean_filename: str) -> None:
    logger.info(f'Downloading {clean_filename} into {filepath}')
    response = await session.get(urljoin(CONFIG['base_url'], filename))

    async with aiofiles.open(os.path.join(filepath, clean_filename), 'wb') as file:
        async for data in response.content.iter_any():
            await file.write(data)


async def get_challenges() -> AsyncIterable[dict[str, str]]:
    logger.debug('Getting challenges')
    challenges = await fetch(urljoin(CONFIG['base_url'], '/api/v1/challenges'))

    if not challenges or not isinstance(challenges, list):
        logger.error('Failed fetching challenges!')
        exit(1)

    for challenge in challenges:
        id = challenge['id']
        challenge_path = f'/api/v1/challenges/{id}'
        url = urljoin(CONFIG['base_url'], challenge_path)

        content = await fetch(url)
        if not content or not isinstance(content, dict):
            logger.warning(f'Failed fetching challenge with id "{id}"!')
            continue

        yield content


def get_clean_filename(url: str) -> str:
    return os.path.basename(urlsplit(url).path)


async def resolve_url(url: str, filepath: str = '.') -> tuple[str, str] | None:
    async with session.get(url) as response:
        try:
            real_url = response.request_info.url.human_repr()
            logger.debug(f'Fetching {real_url}')

            filename = get_clean_filename(real_url)

            logger.info(f'Downloading {filename} into {filepath}')
            async with aiofiles.open(os.path.join(filepath, filename), 'wb') as file:
                async for data in response.content.iter_any():
                    await file.write(data)

            return (url, f'./{filename}')
        except Exception:
            logger.error(f'Failed downloading file from url "{url}"!')
            return None


async def resolve_urls(content: str, filepath: str = '.') -> str:
    results = await gather(*(resolve_url(match[1], filepath) for match in url_pattern.finditer(content)))
    results = filter(None, results)

    for before, after in results:
        content = content.replace(before, after, 1)

    return content


async def dump() -> None:
    hostname = urlparse(CONFIG['base_url']).hostname

    async with aiofiles.open(CONFIG['template'], 'r') as file:
        template = Template(await file.read())

    async for challenge in get_challenges():
        category = re.sub(CONFIG['blacklist'], '', challenge['category']).strip()
        name = re.sub(CONFIG['blacklist'], '', challenge['name']).strip()
        logger.info(f'[{category}] {name}')

        filepath = os.path.join(hostname, category, name)

        if not await aiofiles.os.path.exists(filepath):
            logger.info(f'Creating directory {filepath}')
            os.makedirs(filepath)

        if not CONFIG['no_resolve_urls']:
            challenge['description'] = await resolve_urls(challenge['description'], filepath)

        async with aiofiles.open(os.path.join(filepath, 'README.md'), 'w+', encoding='utf-8') as file:
            rendered = template.render(challenge=challenge)
            await file.write(rendered)

        if CONFIG['no_files']:
            continue

        if 'files' in challenge:
            for filename in challenge['files']:
                clean_filename = get_clean_filename(filename)
                await fetch_file(filepath, filename, clean_filename)


async def main() -> None:
    global session
    async with ClientSession() as session:
        await setup()
        welcome()

        if CONFIG['no_login']:
            await dump()
        else:
            await login()
            await dump()
            await logout()


if __name__ == '__main__':
    run(main())
