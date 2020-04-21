@load base/frameworks/sumstats

event zeek_init()
{
	local r1 = SumStats::Reducer($stream="http_all_resp", $apply=set(SumStats::SUM));
	local r2 = SumStats::Reducer($stream="http_404_resp", $apply=set(SumStats::SUM));
	local r3 = SumStats::Reducer($stream="http_url_404_resp", $apply=set(SumStats::UNIQUE));
	
	SumStats::create([$name="scanner",
                      $epoch=10mins,
                      $reducers=set(r1, r2, r3),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        if("http_all_resp" in result && "http_404_resp" in result && "http_url_404_resp" in result)
                        {
                        	local num_http_all_resp = result["http_all_resp"]$num;
                        	local num_http_404_resp = result["http_404_resp"]$num;
                        	local num_http_url_404_resp = result["http_url_404_resp"]$unique;
                        
                        	if(num_http_all_resp > 2 && num_http_404_resp > 0.2 * num_http_all_resp && num_http_url_404_resp > 0.5 * num_http_404_resp)
                        	{
                        		print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, num_http_404_resp, num_http_url_404_resp);
                        	}
                        }
                        }]);
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
	SumStats::observe("http_all_resp", SumStats::Key($host = c$id$orig_h), SumStats::Observation($num = 1));
	
    if (code == 404)
    {
        SumStats::observe("http_404_resp", SumStats::Key($host = c$id$orig_h), SumStats::Observation($num = 1));
        SumStats::observe("http_url_404_resp", SumStats::Key($host = c$id$orig_h), SumStats::Observation($str = c$http$host+c$http$uri));
    }
}
