import asyncio
import aiohttp
import time

TARGET_URL = "http://10.0.1.12:5000"
TOTAL_REQUESTS = 50_000_000
CONCURRENT_REQUESTS = 1000  # Kolik požadavků běží současně

# Počítadla pro statistiky
success_count = 0
fail_count = 0

sem = asyncio.Semaphore(CONCURRENT_REQUESTS)  # Omezení paralelismu

async def fetch(session):
    global success_count, fail_count
    async with sem:
        try:
            async with session.get(TARGET_URL) as resp:
                if resp.status == 200:
                    success_count += 1
                else:
                    fail_count += 1
        except Exception as e:
            fail_count += 1

async def bound_fetch(session, _):
    await fetch(session)

async def main():
    start = time.time()
    async with aiohttp.ClientSession() as session:
        tasks = [asyncio.create_task(bound_fetch(session, i)) for i in range(TOTAL_REQUESTS)]
        await asyncio.gather(*tasks)
    end = time.time()
    print(f"✅ HOTOVO za {end - start:.2f} sekund")
    print(f"✔️ Úspěšných: {success_count}")
    print(f"❌ Selhalo: {fail_count}")

if __name__ == "__main__":
    asyncio.run(main())
