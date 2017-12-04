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
- Manual mode so that you can test individual domains.
- Certstream mode so that you can enumerate s3 buckets in real time.
- Colorized output for visual grep ;)
- Currently generates over 400 permutations per domain
- `StoreInDB` which will eventually be used to push data to a database

## Usage
- `slurp domain --domain google.com` will enumerate the S3 domains for a specific target.
- `slurp certstream` will follow certstream and enumerate S3 buckets from each domain.
- `permutations.json` stores the permutations that are used by the program; they are in JSON format and loaded during execution **this is required**; it assumes a specific format per permutation: `anything_you_want.%s`; the ending `.%s` is **required** otherwise the AWS S3 URL will not be attached to it, and therefore no results will come from S3 enumeration.

## Installation
- Download from Releases section, or build yourself with `go build` or `build.sh`.

## License
- AGPLv3
