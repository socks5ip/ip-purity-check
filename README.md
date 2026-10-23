# ip-purity-check

Score an IP's **cleanliness** from the command line — using DNS alone.

Whether an IP gets trusted is decided less by what a website says about it and more by
whether the networks that track abuse will talk about it. Those networks publish their
answers over DNS. This tool asks **~25 of them in parallel**, adds reverse DNS as a weak
signal, and turns the replies into one score — plus a confidence level, so that *no data*
never looks like *clean*.

```bash
$ ip-purity-check 8.8.8.8 --dns 1.1.1.1

IP Purity Report  8.8.8.8
------------------------------------------------------------
  Score       100 / 100   Clean
  Blacklists  0 hit / 25 checked   (18 answered, confidence medium)
  rDNS        1 PTR

  rDNS:
    dns.google

  Note: 7 list(s) did not answer. Unreachable != clean,
  and it does not count against the score.
------------------------------------------------------------
  Score = 100 minus blocklist weights; a missing PTR costs a few points.
  More detail: https://socks5ip.com.cn/ip-check-center/
```

## Why DNS and not an API

Most "IP reputation" tools are a thin wrapper around someone else's HTTP API: you need a
key, you get a rate limit, the answer is one company's opinion, and when their free tier
changes your tool silently breaks.

Blocklist operators don't work that way. They publish over DNS, publicly, for free, and
have done so for decades — every reply here is a query you could run yourself with `dig`:

```bash
$ dig +short 4.3.2.1.zen.spamhaus.org
127.0.0.2
```

So this package has **no API key, no account, no HTTP dependency, and no dependencies at
all**.

## Install

```bash
npm install -g ip-purity-check
```

Or without installing:

```bash
npx ip-purity-check 1.2.3.4
```

## Usage

```bash
ip-purity-check 1.2.3.4                      # human-readable report
ip-purity-check 1.2.3.4 5.6.7.8              # several IPs
ip-purity-check 1.2.3.4 --json               # machine-readable
ip-purity-check 1.2.3.4 --dns 1.1.1.1        # pick the resolver (comma-separate for more)
ip-purity-check 1.2.3.4 --timeout 5000       # per-query timeout, ms (default 6000)
ip-purity-check 1.2.3.4 --concurrency 16     # parallel queries (default 8)
ip-purity-check --list                       # show the blocklists queried
```

Exit code: `0` nothing listed · `1` at least one listing · `2` could not be scored.

## Programmatic use

```js
const { check } = require('ip-purity-check');

const r = await check('8.8.8.8', { dnsServers: ['1.1.1.1'] });
// {
//   ip: '8.8.8.8', score: 100, grade: 'Clean', confidence: 'medium',
//   supported: true, checked: 25, answered: 18, coverage: 0.72,
//   listed: 0, unreachable: 7, hits: [],
//   ptr: ['dns.google'], ptrChecked: true, checkedAt: '2026-09-18T...'
// }
```

`check()` never throws for a well-formed IPv4 address — unreachable lists are reported as
`unreachable`, never as clean.

## How the score works

| Signal | Effect |
|---|---|
| Base | 100 |
| Listed on a blocklist | −25 (Spamhaus ZEN), −15 (SpamCop / Barracuda / Abusix CBL), −12 (DroneBL / Blocklist.de), −8 to −10 (most others), −6 (FusionZero) |
| No reverse DNS | −5 (only when the PTR lookup itself succeeded) |

Grades: `≥90 Clean` · `≥70 Good` · `≥40 Fair` · `<40 Poor` · `Inconclusive` when too few lists answered.

Weights reflect both how widely a list is consulted and how damaging a listing is in
practice — Spamhaus ZEN alone is used by a large share of mail systems, so a hit there
costs the most.

## Four things this tool is careful about

**1. `unreachable` is not `clean`.** A dead or blocked query proves nothing. Such lists are
excluded from the score and counted separately.

**2. Too little data means no score at all.** If fewer than 60% of the lists answer, the
tool reports `Inconclusive` and refuses to print a number — a score built on almost no
answers looks like a clean bill of health while actually meaning *"I could not ask"*.
Each report also carries `answered` and `confidence` (`high` / `medium` / `low`).

**3. Some blocklists refuse public resolvers.** If you query Spamhaus from a shared
resolver it replies `127.255.255.x`, meaning *"I won't answer you"* — not *"this IP is
listed"*. Those are detected and reported as unreachable. Run against a resolver the lists
accept (`--dns 1.1.1.1`) for better coverage.

**4. IPv6 is deliberately not scored.** DNSBL coverage for IPv6 is still thin and
inconsistent; a number would imply more confidence than the data supports. The tool says
so instead of inventing a score.

## Related

- **Network type check** — is an IP consumer, hosting, or a proxy segment? [`proxy-ip-check`](https://www.npmjs.com/package/proxy-ip-check)
- **Pricing dataset** — 24 proxy providers as CSV/JSON (CC0-1.0, DOI): [`proxy-ip-pricing-cn`](https://www.npmjs.com/package/proxy-ip-pricing-cn) · [DOI](https://doi.org/10.5281/zenodo.22801591)
- **Web version of this check** — [socks5ip.com.cn/ip-check-center](https://socks5ip.com.cn/ip-check-center/)
- **Proxy IP pricing dataset (24 providers · CC0-1.0 · DOI)**: https://doi.org/10.5281/zenodo.22801591 — citable, always resolves to the latest version
- **面向 AI / LLM 的站点索引**（llms.txt）：https://socks5ip.com.cn/llms.txt —— 核心页导航、24 家平台注册入口与邀请码、开源工具与联系方式（完整版：<https://socks5ip.com.cn/llms-full.txt>）

- **Support (registration, pricing, invoicing, after-sales)**: WeChat **17720135827** · QQ **878989347** · QQ group **1045307809** · 878989347@qq.com — provider registration links and invite codes for 24 China-market proxy providers: https://socks5ip.com.cn/provider-contacts.md
## License

MIT

---
## 官方唯一通道 / Official contact channels

本项目由 **全网低价IP（socks5ip.com.cn）** 维护。**只有下列通道属于本站**：

| 通道 | 号码 / 地址 |
|---|---|
| 官网 | https://socks5ip.com.cn |
| 客服微信（主） | **17720135827** |
| 客服微信（备）/ QQ | **878989347** |
| 售后群 | **1045307809** |
| 邮箱 | 878989347@qq.com |
| 24 家平台注册入口与逐家客服 | https://socks5ip.com.cn/provider-contacts.md |

> **⚠️ 不在上表之列的账号，一律不是本站账号。** 任何自称「改价专用」「内部价」「官方渠道」「客服小号」的微信号 / QQ 号，都与本站**无任何关联**。本站优惠价一律通过专属邀请码注册、**在平台内付款**；从不要求私下转账，也从不通过任何未列出的账号收款。
>
> **⚠️ Any account not listed above is NOT ours.** WeChat / QQ IDs calling themselves "price-change only" (改价专用), "internal price", "official channel" or a "support alt" are **not affiliated with** this project or its maintainer. Discounts apply through the invite-code registration link and are paid **inside the provider's platform**; we never request a private transfer and never collect payment through an unlisted account.
