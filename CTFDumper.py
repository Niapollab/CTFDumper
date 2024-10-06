#!/usr/bin/env python3
from argparse import ArgumentParser
from jinja2 import Template
from aiohttp import ClientSession
from urllib.parse import urljoin, urlparse, urlsplit
import logging
import logging.config
import os
import re
import aiofiles
import aiofiles.os
from asyncio import run, gather


banner = r"""
┏┓┏┳┓┏┓┳┓
┃  ┃ ┣ ┃┃┓┏┏┳┓┏┓┏┓┏┓
┗┛ ┻ ┻ ┻┛┗┻┛┗┗┣┛┗ ┛
  by Niapoll  ┛ v1.0
"""


CONFIG = {
    'username': None,
    'password': None,
    'nonce_regex': 'name="nonce"(?:[^<>]+)?value="([0-9a-f]{64})"',
    'base_url': None,
    'no_files': None,
    'no_resources': None,
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
        '--no-resources',
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
    CONFIG['no_resources'] = args.no_resources
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


async def fetch_json(url: str) -> list[dict[str, str]] | dict[str, str] | None:
    logger.debug(f'Fetching {url}')

    response = await session.get(url)
    json = await response.json()

    return json['data'] if response.ok and json['success'] else None


async def fetch_file(filepath: str, filename: str) -> None:
    clean_filename = get_clean_filename(filename)

    logger.info(f'Downloading {clean_filename} into {filepath}')
    response = await session.get(urljoin(CONFIG['base_url'], filename))

    async with aiofiles.open(os.path.join(filepath, clean_filename), 'wb') as file:
        async for data in response.content.iter_any():
            await file.write(data)


async def get_challenges() -> list[dict[str, str]]:
    logger.debug('Getting challenges')

    url = urljoin(CONFIG['base_url'], '/api/v1/challenges')
    challenges = await fetch_json(url)

    if not challenges or not isinstance(challenges, list):
        logger.error('Failed fetching challenges!')
        exit(1)

    return challenges


def get_clean_filename(url: str) -> str:
    return os.path.basename(urlsplit(url).path)


async def fetch_resource(url: str, filepath: str = '.') -> tuple[str, str] | None:
        try:
            async with session.get(url) as response:
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


async def fetch_resources(content: str, filepath: str = '.') -> str:
    results = filter(None, await gather(
        *(fetch_resource(match[1], filepath) for match in url_pattern.finditer(content))
    ))

    for before, after in results:
        content = content.replace(before, after, 1)

    return content


async def fetch_readme(challenge: dict[str, str], template: Template, filename: str) -> None:
    async with aiofiles.open(filename, 'w+', encoding='utf-8') as file:
        rendered = template.render(challenge=challenge)
        await file.write(rendered)


async def fetch_challenge(challenge_info: dict[str, str], hostname: str, template: Template) -> None:
    id = challenge_info['id']
    challenge_path = f'/api/v1/challenges/{id}'
    url = urljoin(CONFIG['base_url'], challenge_path)

    challenge = await fetch_json(url)
    if not challenge or not isinstance(challenge, dict):
        logger.warning(f'Failed fetching challenge with id "{id}"!')
        return

    category = re.sub(CONFIG['blacklist'], '', challenge['category']).strip()
    name = re.sub(CONFIG['blacklist'], '', challenge['name']).strip()
    logger.info(f'[{category}] {name}')

    filepath = os.path.join(hostname, category, name)

    if not await aiofiles.os.path.exists(filepath):
        logger.info(f'Creating directory {filepath}')
        os.makedirs(filepath)

    fetch_resources_task = fetch_resources(challenge['description'], filepath) \
        if not CONFIG['no_resources'] \
        else None

    fetch_files_task = []
    if not CONFIG['no_files'] and 'files' in challenge:
        for filename in challenge['files']:
            fetch_files_task.append(fetch_file(filepath, filename))

    await gather(*fetch_files_task)

    if fetch_resources_task:
        challenge['description'] = await fetch_resources_task

    await fetch_readme(challenge, template, os.path.join(filepath, 'README.md'))


async def dump() -> None:
    hostname = urlparse(CONFIG['base_url']).hostname

    async with aiofiles.open(CONFIG['template'], 'r') as file:
        template = Template(await file.read())

    await gather(
        *(fetch_challenge(challenge, hostname, template) for challenge in await get_challenges())
    )


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
