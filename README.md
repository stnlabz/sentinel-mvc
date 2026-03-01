# sentinel-mvc
The Sentinel Project in MVC Format

Utilizes the Data controllers of the Indicia MVC project

- Gathers intelligence from the STN-Labz API
- Auto blocks on known bad IP's
- Does a pre check on visitors and blocks if necessary
- Reports block to the API immediately
- Does an hourly check on API updates
- Auto populates DB content from API Ingestion

## Updates
Set static to be used in `/app/bootstrap.php` so Sentinel does what it is intended to do, check and block, then report to the API.
```php
public static function inspect(): void 
{
    -- method content
}
```
