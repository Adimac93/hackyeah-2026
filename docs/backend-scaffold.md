# Design spec

- Rust Workspace
- Uses libraries such as:
	- axum
	- dotenvy
	- tokio
	- sqlx with database schema on supabase
- Integrates with Supabase
- Uses justfile for essential project actions
- Deployment Dockerfile based on cargo chef image
