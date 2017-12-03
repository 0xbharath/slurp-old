# slurp
Enumerates S3 buckets manually or via certstream

## Overview
- First of all, credit to https://github.com/eth0izzle/bucket-stream for the certstream idea
- Not responsible for how you use this tool.

![certstream](https://i.imgur.com/6JUDNI5.png)

![manual](https://i.imgur.com/d28yX1Y.png)

### Features
- Written in Go:
    - It's faster than python
    - No dependency hell and version locks (ie python 3 and requirements.txt, etc)
    - Better concurrency
    - Static binary that you can use on any ELF64 linux
- Manual mode so that you can test individual domains.
- Certstream mode so that you can enumerate s3 buckets in real time.
- Colorized output for visual grep ;)

## Usage
- `slurp domain --domain google.com` will enumerate the S3 domains for a specific target.
- `slurp certstream` will follow certstream and enumerate S3 buckets from each domain.

## Installation
- Download from Releases section, or build yourself with `go build`.

## License
- AGPLv3
