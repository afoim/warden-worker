const url = "https://warden.2x.nz/identity/connect/token";

async function main() {
  const ip = "203.0.113.10";
  for (let i = 1; i <= 35; i++) {
    const body =
      "grant_type=password" +
      "&username=none%40example.com" +
      "&password=x" +
      "&deviceIdentifier=d" +
      "&deviceName=n" +
      "&deviceType=0" +
      "&scope=api+offline_access" +
      "&client_id=mobile";

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "x-forwarded-for": ip,
      },
      body,
    });

    const t = await r.text();
    if ([1, 30, 31, 35].includes(i)) {
      console.log(i, r.status, t);
    }
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

