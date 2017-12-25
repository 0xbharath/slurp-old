# slurp
Enumerates S3 buckets manually or via certstream

## Overview
- First of all, credit to https://github.com/eth0izzle/bucket-stream for the certstream idea
- Also, credit to all the vendor packages that made this tool possible
- Not responsible for how you use this tool.

![certstream](https://i.imgur.com/6JUDNI5.png)

![manual](https://i.imgur.com/d28yX1Y.png)

### Features
- Written in Go:
    - It's faster than python
    - No dependency hell and version locks (ie python 3 and requirements.txt, etc)
    - Better concurrency
    - Punycode support for internationalized domains (S3 doesn't allow internationalized buckets; so this app just notifies and skips (certstream) or exits (manual mode))
- Domain mode so that you can test individual domains.
- **New** Keywords mode so that you can attempt enumeration based on keywords.
- Certstream mode so that you can enumerate s3 buckets in real time.
- Colorized output for visual grep ;)
- Currently generates over 400 permutations per domain
- `StoreInDB` which will eventually be used to push data to a database
- Strong copyleft license

## Usage
- `slurp domain <-t|--target> google.com` will enumerate the S3 domains for a specific target.
- `slurp keyword <-t|--target> linux,golang,python` will enumerate S3 buckets based on those 3 key words.
- `slurp certstream` will follow certstream and enumerate S3 buckets from each domain.
- `permutations.json` stores the permutations that are used by the program; they are in JSON format and loaded during execution **this is required**; it assumes a specific format per permutation: `anything_you_want.%s`; the ending `.%s` is **required** otherwise the AWS S3 URL will not be attached to it, and therefore no results will come from S3 enumeration. If you need flexible permutations then you have to [edit the source](https://github.com/bbb31/slurp/blob/master/main.go#L361).

## Installation
- Download from Releases section, or build yourself with `go build` or `build.sh`.
    - **Make sure you clone to `$GOPATH/src` or you will get build errors!**

## License
- AGPLv3
