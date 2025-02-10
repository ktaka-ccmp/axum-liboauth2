# Store Management in axum-liboauth2

This document explains how storage is configured and managed in the axum-liboauth2 library.

## Environment Configuration

### Token Store Configuration
```env
# Choose the token store type (memory/redis)
OAUTH2_TOKEN_STORE=redis

# Redis configuration (if using redis store)
OAUTH2_TOKEN_REDIS_URL=redis://localhost:6379
```

### Session Store Configuration
```env
# Choose the session store type (memory/redis)
OAUTH2_SESSION_STORE=redis

# Redis configuration (if using redis store)
OAUTH2_SESSION_REDIS_URL=redis://localhost:6379

# Session configuration
SESSION_COOKIE_NAME=session
SESSION_COOKIE_MAX_AGE=600  # in seconds
```

## Singleton Pattern vs State Pattern

### Singleton Pattern (Our Approach)

We use a singleton pattern for both token and session stores. Here's the structure:

```rust
pub(crate) static TOKEN_STORE: LazyLock<Mutex<Box<dyn CacheStoreToken>>> =
    LazyLock::new(|| Mutex::new(Box::new(InMemoryTokenStore::new())));
```

#### Benefits of Singleton
1. **Global Access**: Any part of the application can access the store without passing references
2. **Single Source of Truth**: Only one instance exists
3. **Thread Safety**: Protected by `Mutex`
4. **Lazy Initialization**: Only created when first accessed
5. **Runtime Configuration**: Can be configured via environment variables

#### Implementation Details
1. **Type Structure**:
```text
static STORE: LazyLock<Mutex<Box<dyn StoreTrait>>>
    |           |      |    |
    |           |      |    +-- Trait object (allows switching implementations)
    |           |      +------- Heap allocation (Box)
    |           +-------------- Thread-safe interior mutability (Mutex)
    +--------------------------- Lazy initialization (LazyLock)
```

2. **Initialization**:
```rust
// Called during application startup
liboauth2::init().await?;
libsession::init().await?;
```

3. **Store Switching**:
```rust
// The store implementation can be changed at runtime
let new_store = store_type.create_store().await?;
*TOKEN_STORE.lock().await = new_store;
```

### State Pattern (Alternative Approach)

The state pattern would involve passing store references through application state:

```rust
#[derive(Clone)]
struct AppState {
    token_store: Arc<dyn TokenStore>,
    session_store: Arc<dyn SessionStore>,
}

let app = Router::new()
    .route("/", get(handler))
    .with_state(app_state);
```

#### Why We Didn't Choose State Pattern
1. **Complexity**: Requires passing state through all handlers
2. **Flexibility**: Harder to switch implementations at runtime
3. **Boilerplate**: More code needed to set up and manage state
4. **Integration**: More complex integration with external libraries
5. **Testing**: Can be more complex to mock in tests

## Best Practices

1. **Initialization**:
   - Always call `init()` before using the library
   - Handle initialization errors appropriately
   - Set environment variables before initialization

2. **Store Selection**:
   - Use in-memory store for development/testing
   - Use Redis store for production
   - Consider your scaling needs when choosing

3. **Error Handling**:
   - Handle store initialization failures
   - Have fallback strategies (e.g., fallback to memory store)
   - Log store-related errors appropriately

4. **Configuration**:
   - Use environment variables for configuration
   - Document all configuration options
   - Provide sensible defaults

## Future Considerations

1. **Additional Store Types**:
   - SQLite support planned
   - PostgreSQL support planned
   - Custom store implementations possible

2. **Migration Support**:
   - Data migration between store types
   - Store type switching without data loss
   - Backup and restore functionality

3. **Monitoring**:
   - Store health checks
   - Performance metrics
   - Error rate tracking
