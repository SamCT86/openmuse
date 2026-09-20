# Signed audit checkpoints

`create_checkpoint` signs the current verified chain length, head hash, and timestamp with a host-held key. Publish the JSON checkpoint to an independent append-only store (object retention, transparency log, or another administrative domain). Later verification detects local history rewrite but does not by itself prove the publication time; the external store supplies that property.
