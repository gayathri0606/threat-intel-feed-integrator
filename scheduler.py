from apscheduler.schedulers.blocking import BlockingScheduler

from refresh_iocs import refresh_all_iocs


# -----------------------------
# CREATE SCHEDULER
# -----------------------------

scheduler = BlockingScheduler()


# -----------------------------
# SCHEDULE IOC REFRESH
# -----------------------------

scheduler.add_job(
    refresh_all_iocs,
    trigger="interval",
    hours=6,
    id="ioc_refresh_job",
    name="Refresh stored IOC intelligence",
    max_instances=1,
    coalesce=True
)


# -----------------------------
# START SCHEDULER
# -----------------------------

print("Threat Intelligence Scheduler Started")
print("Stored IOCs will refresh every 6 hours.")
print("Press Ctrl + C to stop.\n")


try:

    scheduler.start()


except (KeyboardInterrupt, SystemExit):

    print("\nScheduler stopped.")