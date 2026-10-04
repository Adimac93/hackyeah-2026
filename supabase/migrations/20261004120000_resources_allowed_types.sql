-- Resources accept only presentations (PPTX), raster images and plain text.
-- Storage enforces this on every upload, whatever the client sends. SVG is
-- left out on purpose: it can carry script. Keep in step with UPLOAD_TYPES in
-- web/src/lib/resources.ts.

update storage.buckets
set allowed_mime_types = array[
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'image/avif',
  'text/plain'
]
where id = 'resources';
