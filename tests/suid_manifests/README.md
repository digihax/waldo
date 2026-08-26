# Captured base-image SUID manifests (provenance for §4.1)

Each `*.txt` is the exact set of setuid-root binary **basenames** in a pristine official container image,
captured with:

```
docker run --rm <image> sh -c "find / -xdev -perm -4000 -type f 2>/dev/null | while read f; do basename \$f; done | sort -u"
```

These are *minimal base-image* flavors. A real deployed box with extra packages (sudo, pkexec, openssh, …) will
legitimately show those as non-stock — by design, since they are not in the pinned reference. The baseline therefore
uses these for **ranking context only** and never claims `high` (confidence caps at `family-detected`).

`baseline_stock_suid` returns a per-build delta **only** for a `family+major` that has its own captured manifest here;
`tests/fixtures.sh` asserts the production **effective** set (`generic STD_SUID ∪ delta`) is **exactly equal** to that
family's manifest (equality, not subset), and fails if any production profile lacks its own manifest file.

The EL9 derivatives are **not** identical, so each has its own manifest: `rockylinux:9` ships `userhelper`;
`almalinux:9` lacks `passwd` and `userhelper`; `oraclelinux:9` lacks `userhelper`. `rhel:9`/`centos-stream:9` are not
freely pullable, so they carry **no** delta and fall through to the conservative generic set (`family-detected`).

| file | image | RepoDigest |
|------|-------|-----------|
| debian-12.txt     | `debian:12`        | `debian@sha256:9344f8b8992482f80cba753f323adeaf17690076c095ccff6cc9536be98185dc` |
| ubuntu-22.04.txt  | `ubuntu:22.04`     | `ubuntu@sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982` |
| ubuntu-24.04.txt  | `ubuntu:24.04`     | `ubuntu@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90` |
| rockylinux-9.txt  | `rockylinux:9`     | `rockylinux@sha256:d7be1c094cc5845ee815d4632fe377514ee6ebcf8efaed6892889657e5ddaaa6` |
| almalinux-9.txt   | `almalinux:9`      | `almalinux@sha256:d2515c769e7b73f95c4fde38c0a505336ff38f14990c0b7253b77060a049a743` |
| oraclelinux-9.txt | `oraclelinux:9`    | `oraclelinux@sha256:e749594d8f9e546a57670ea4943c8eeff86dfb237bbea4febd859dd06ccbedc0` |

Captured 2026-07-22.
