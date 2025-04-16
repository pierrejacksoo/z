import gps

session = gps.gps(mode=gps.WATCH_ENABLE)

while True:
    report = session.next()
    if report['class'] == 'TPV':
        print("Latitude:", getattr(report, 'lat', None))
        print("Longitude:", getattr(report, 'lon', None))
        break
