# asp-core-google-jwt
Verify JWT tokens provided by Google Firebase within ASP CORE

## To run the app you need to:
 - Install .NET Core [FROM HERE](https://www.microsoft.com/net/core#windows)
 - Run: **dotnet restore**
 - Run: **dotnet build**
 - Run: **dotnet run**

 The application should be available on `http://localhost:5000`.

 Try making a request to `http://localhost:5000/api/values`. If no authentication header is provided, you should get a `HTTP 401` error.

 Get hold of a Google Firebase ID token ([MORE HERE](https://firebase.google.com/docs/auth/admin/verify-id-tokens)) and repeat the above call with the following header:
  > `Authorization: Bearer <the_id_token>`

  The link above provides the details of this implementation (verifying ID Tokens using Google signing certificates).

  If the authorization was sucessful, the response should be:
  ```json
  [
	"value1",
	"value2"
  ]
  ```

  ## Configuration

  Out of the box, the Issuer and Audience validation has been disabled. To enable them make sure to:
   - Include a settings section in the `appsettings.json` file, called "`JwtIssuerOptions`":

```json
	"JwtIssuerOptions": {
		"Issuer": "https://securetoken.google.com/my-awesome-app-name",
		"Audience": "my-awesome-app-name"
	}
``` 

  - In `Startup.cs` set the following to `true`:
	 - `ValidateIssuer`
	 - `ValidateAudience`

