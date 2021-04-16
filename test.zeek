@load base/frameworks/sumstats
global totalres: count=0;
event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="http.lookup", $apply=set(SumStats::UNIQUE,SumStats::SUM));
    SumStats::create([$name="http.scans.404.unique",
                      $epoch=10mins,
                      $reducers=set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r = result["http.lookup"];
                        if(r$num>2&&r$unique/r$num>0.5){
                        if(r$num/totalres>0.2)
                        print fmt("%s is a scanner with %d scan attempts on %d urls", key$host, r$num, r$unique); 
                        }
                        }
                        ]);
    }

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    ++totalres;
    if (code==404)
        SumStats::observe("http.lookup", [$host=c$id$orig_h], [$str=reason]);
    }
