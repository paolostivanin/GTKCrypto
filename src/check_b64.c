#include <gtk/gtk.h>    
#include <glib.h>
#include <glib/gstdio.h>


const gchar alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=+/";


gint
check_b64 (const gchar *input)
{
	gsize input_len = g_utf8_strlen (input, -1);
	
	gsize i, j, z = 0, line_wrap = 0, useless_chars = 0;
	
	i = input_len - 1;
	
	while (input[i] == '\n' || input[i] == '\t')
	{
		useless_chars++;
		i--;
	}

	input_len -= useless_chars;
	
	for (i = 0; i < input_len; i++)
	{
		if (i == input_len - 2)
			if (input[i] == '=' && input[i+1] == '=')
				goto end;
				
		if (i == input_len - 1)
			if (input[i] == '=')
				goto end;
				
		for (j = 0; j < sizeof (alphabet); j++)
		{
			if (input[i] == '\n')
			{
				line_wrap++;
				break;
			}
			if (input[i] == alphabet[j])
			{
				z++;
				break;
			}
		}
	}
	
	if ((input_len - line_wrap) % 4 != 0)
		return -1;
		
	if (z != (input_len - line_wrap))
		return -1;
	
	else
		return 0;
		
	end:
	return 0;
}
