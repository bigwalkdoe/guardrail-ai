from celery import shared_task


@shared_task(name="app.tasks.maintenance.cleanup_resolved_alerts")
def cleanup_resolved_alerts(days=30):
    """Clean up resolved alerts older than specified days."""
    pass


@shared_task(name="app.tasks.maintenance.warm_cache")
def warm_cache():
    """Warm up cache with frequently accessed data."""
    pass
