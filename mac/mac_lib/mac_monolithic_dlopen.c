#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <sasl.h>
#include "saslint.h"

#include <sasl_plain_plugin_decl.h>
#undef sasl_server_plug_init
#undef sasl_client_plug_init

#include <sasl_anonymous_plugin_decl.h>
#undef sasl_server_plug_init
#undef sasl_client_plug_init

#include <sasl_cram_plugin_decl.h>
#undef sasl_server_plug_init
#undef sasl_client_plug_init

#include <sasl_md5_plugin_decl.h>
#undef sasl_server_plug_init
#undef sasl_client_plug_init

#include <sasl_scram_plugin_decl.h>
#undef sasl_server_plug_init
#undef sasl_client_plug_init

#include <sasl_kerberos4_plugin_decl.h>
#undef sasl_server_plug_init
#undef sasl_client_plug_init

#include <stdio.h>

/* gets the list of mechanisms */
int _sasl_get_mech_list(const char *entryname,
			const sasl_callback_t *getpath_cb,
			const sasl_callback_t *verifyfile_cb,
			int (*add_plugin)(void *,void *))
{
	if(strcmp(entryname,"sasl_client_plug_init")==0) {
		(*add_plugin)(kerberos4_sasl_client_plug_init,(void*)1);
		(*add_plugin)(anonymous_sasl_client_plug_init,(void*)1);
		(*add_plugin)(cram_sasl_client_plug_init,(void*)1);
		(*add_plugin)(scram_sasl_client_plug_init,(void*)1);
		(*add_plugin)(md5_sasl_client_plug_init,(void*)1);
		(*add_plugin)(plain_sasl_client_plug_init,(void*)1);
	} else if(strcmp(entryname,"sasl_server_plug_init")==0) {
		(*add_plugin)(kerberos4_sasl_server_plug_init,(void*)1);
		(*add_plugin)(anonymous_sasl_server_plug_init,(void*)1);
		(*add_plugin)(cram_sasl_server_plug_init,(void*)1);
		(*add_plugin)(scram_sasl_server_plug_init,(void*)1);
		(*add_plugin)(md5_sasl_server_plug_init,(void*)1);
		(*add_plugin)(plain_sasl_server_plug_init,(void*)1);
	} else
		return SASL_BADPARAM;
	
  	return SASL_OK;
}

int _sasl_done_with_plugin(void *plugin)
{
  if (! plugin)
    return SASL_BADPARAM;

  return SASL_OK;
}
