addOnloadHook(function()
	{
		attachHook('login_build_form', 'http_auth_login_hook(table, data);');
	});

function http_auth_login_hook(table, data)
{
	if ( window.shift )
		return;
	
	if (window.logindata.user_level <= USER_LEVEL_MEMBER)
	{
		window.location = makeUrlNS('Special', 'LoginHTTP');
	}
	else
	{
		// re-auth
		ajaxGet(makeUrlNS('Special', 'LoginHTTP', 'ajax&level=' + window.logindata.user_level), function(xhr)
			{
				if ( xhr.readyState == 4 && xhr.status == 200 ) {
					var result = JSON.parse(xhr.responseText);
					if ( result.result == 'success' ) {
						window.logindata.successfunc(result.sid);
					}
				}
			});
	}
}
