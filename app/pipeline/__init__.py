"""Background full-dataset pipeline run: load + scan in a thread."""
from app.pipeline.background_run import start_full_pipeline, get_full_pipeline_status

__all__ = ["start_full_pipeline", "get_full_pipeline_status"]
