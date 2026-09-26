const key = process.env.C2PA_API_KEY
const url = process.argv[2]
if (!key || !url) {
  console.error('usage: C2PA_API_KEY=... node node.mjs <url>')
  process.exit(2)
}

const response = await fetch('https://api.c2pa.design/v1/verifications', {
  method: 'POST',
  headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
  body: JSON.stringify({ url }),
})

if (!response.ok) {
  const { error } = await response.json()
  console.error(`${error.code}: ${error.message}`)
  process.exit(1)
}

const { result } = await response.json()
console.log(result.credential.status, '·', result.signer?.organization ?? 'no signer')
process.exit(result.credential.status === 'valid_trusted' ? 0 : 1)
