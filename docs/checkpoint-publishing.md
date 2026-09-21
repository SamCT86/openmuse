# Publish signed audit checkpoints

A local signature detects changed checkpoint content. Publishing its canonical JSON to an independently administered append-only store adds evidence that the checkpoint existed outside the host at a particular time.

`HTTPSPutPublisher` targets a pre-authorized HTTPS PUT URL. A typical deployment uses a presigned S3 URL for a bucket with versioning, Object Lock, retention, and delete permissions held by a separate administrator.

```python
from openmuse.audit_anchor import create_checkpoint
from openmuse.checkpoint_publisher import HTTPSPutPublisher

checkpoint = create_checkpoint(audit_path, signing_key)
publisher = HTTPSPutPublisher("https://archive.example/anchors/{key}?signature=...")
receipt = publisher.publish(checkpoint, f"{checkpoint.records}-{checkpoint.head_hash}.json")
print(receipt.sha256, receipt.version)
```

Use a new object key for every checkpoint. The publisher sends `If-None-Match: *`, refuses redirects and non-HTTPS URLs, requires a success status, and returns the response version/ETag when supplied. The destination, not this client, must enforce retention and reject overwrite or deletion. Keep presigned URLs and receipts out of planner context and audit payloads.
