"""Gemma local LLM integration forwarding to brain.py"""

from backend.pipeline.brain import BrainEngine, Brain, AIBrain

class GemmaEngine(BrainEngine):
    """Gemma threat reasoning engine (forwards to BrainEngine)"""
    pass

__all__ = ["GemmaEngine", "BrainEngine", "Brain", "AIBrain"]
