#include "ui.h"
#include "config.h"
#include "misc.h"
#include "a_string.h"
#include "http_download.h"
#include <curl/curl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#ifndef _WIN32
#include <libgen.h>
#endif

static int progress_download(void *clientp, double dltotal, double dlnow, double ultotal, double ulnow)
{
    UNUSED(ultotal);
    UNUSED(ulnow);

    if (dltotal==0)
        return !ui_inprogress_pulse(clientp);
    return !ui_inprogress_set_fraction(clientp,dlnow/dltotal);
}


int http_download(const char *src_url, const char *dst_filename)
{
    CURL *curl;
    CURLcode res = CURLE_FAILED_INIT;
    void *progress;  
    a_string_t *user_agent;
    a_string_t *create_dst_filename;
    a_string_t *progress_title;
#ifndef _WIN32
    a_string_t *copy_dst_filename;
    char *_dirname;
#else
    char _dirname[_MAX_FNAME];
#endif
    FILE *temp_fd;
    
    curl = curl_easy_init();
    
    if (!curl)
        return 0;

    progress_title    = a_strnew(NULL); 
    a_sprintf(progress_title,"Updating %s",dst_filename);
    
    user_agent = a_strnew(NULL);     
    a_sprintf(user_agent,"cardpeek/%s",VERSION);

    progress = ui_inprogress_new(a_strval(progress_title),"Please wait...");

    create_dst_filename = a_strnew(NULL);
#ifndef _WIN32
    copy_dst_filename = a_strnew(NULL);
    a_sprintf(copy_dst_filename,"%s",dst_filename);
    _dirname = dirname(copy_dst_filename->_data);
    a_sprintf(create_dst_filename,"mkdir -p %s",_dirname);
    system(create_dst_filename->_data);
#else
    _splitpath(dst_filename, NULL, _dirname, NULL, NULL);
    a_sprintf(create_dst_filename,"mkdir \"%s\"",_dirname);
    system(create_dst_filename);
#endif
    temp_fd = fopen(dst_filename,"wb");
    if (!temp_fd) {
    	log_printf(LOG_ERROR,"Destination file could not be opened: %s", dst_filename);
    	goto exit;
    }

    curl_easy_setopt(curl,CURLOPT_URL,src_url);
    curl_easy_setopt(curl,CURLOPT_WRITEDATA, temp_fd);
    curl_easy_setopt(curl,CURLOPT_USERAGENT, a_strval(user_agent));
    curl_easy_setopt(curl,CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl,CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl,CURLOPT_PROGRESSFUNCTION, progress_download);
    curl_easy_setopt(curl,CURLOPT_PROGRESSDATA, progress);
    curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION, 1L); 

    res = curl_easy_perform(curl);

    fclose(temp_fd);

    if (res!=CURLE_OK)
    {
        log_printf(LOG_ERROR,"Failed to fetch %s: %s", src_url, curl_easy_strerror(res));
        unlink(dst_filename);
    }

    curl_easy_cleanup(curl);

exit:
    ui_inprogress_free(progress);

    a_strfree(user_agent);
    a_strfree(progress_title);
    a_strfree(create_dst_filename);
#ifndef _WIN32
    a_strfree(copy_dst_filename);
#endif

    return (res==CURLE_OK);
} 
