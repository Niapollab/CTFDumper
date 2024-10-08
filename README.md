# CTFDumper

A tool for dumping CTFd challenges.

## Usage

```
usage: CTFDumper.py [-h] [-u USERNAME] [-p PASSWORD] [--nonce-regex NONCE_REGEX] [--auth-file AUTH_FILE] [-n] [--no-logo] [--no-files] [--no-resources] [--trust-all] [-t TEMPLATE] [-v] url

A tool for dumping CTFd challenges

positional arguments:
  url                   Platform URL

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Platfrom username
  -p PASSWORD, --password PASSWORD
                        Platform password
  --nonce-regex NONCE_REGEX
                        Platform nonce regex
  --auth-file AUTH_FILE
                        File containing username and password, seperated by newline
  -n, --no-login        Use this option if the platform does not require authentication
  --no-logo             Do not print logo on startup
  --no-files            Do not download files
  --no-resources        Do not download resources from embedded urls in description
  --trust-all           Will make directory as the name of the challenge, the slashes(/) character will automatically be replaced with underscores(_)
  -t TEMPLATE, --template TEMPLATE
                        Custom template path
  -v, --verbose         Verbose
```

## Template

The template is rendered with Jinja2.

For [this challenge](https://demo.ctfd.io/challenges#Hej), the template below

```
title: {{ challenge['name'] }}
value: {{ challenge['value'] }}
description: {{ challenge['description'] }}
```

Will generate the following output

```
title: Hej
value: 42
description: Hallo
```

## Notes

- Using `--auth-file` rather than typing your username/password in the command is consider safe.
- `--trust-all` allows non-ASCII characters to be the name of the directory.
