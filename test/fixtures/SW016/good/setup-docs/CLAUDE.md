# Setup

1. Create a key in the dashboard and export it: `export TRACKER_API_KEY=your-api-key-here`.
2. Never commit `.env`; the token lives in `$TRACKER_API_KEY`.
3. For local tests use `"api_key": "FAKE_KEY_local_development_only"`.
4. The client reads `Authorization: Bearer $TRACKER_API_KEY` from the environment.
