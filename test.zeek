global httprecrdTable :table[addr] of set[time,count,string] ;

global mintimeTable :table[addr] of time = {};
global maxtimeTable :table[addr] of time = {};
global replycounterIn10MinsTable :table[addr] of count = {};
global _400counterIn10MinsTable :table[addr] of count = {};
global urlsetIn10MinsTable: table[addr] of set[string] = {};

global problemIP :set[string] = {};

event http_reply(c: connection, version: string, code: count, reason: string)
{
	local t1 = network_time();
	
	if(c$id$orig_h in httprecrdTable)
	{
		add httprecrdTable[c$id$orig_h][t1,code,c$http$uri];
	
		if (t1 > maxtimeTable[c$id$orig_h]){maxtimeTable[c$id$orig_h]=t1;}
		++replycounterIn10MinsTable[c$id$orig_h];
		if (code == 404){++_400counterIn10MinsTable[c$id$orig_h];}
		if (c$http$uri !in urlsetIn10MinsTable[c$id$orig_h]){ add urlsetIn10MinsTable[c$id$orig_h][c$http$uri];}
	}
	else
	{
		local a :set[time,count,string];
		local b :set[string];
		local d :set[string];
		
		httprecrdTable[c$id$orig_h] = a;
		add httprecrdTable[c$id$orig_h][t1,code,c$http$uri];
		
		mintimeTable[c$id$orig_h] = t1;
		maxtimeTable[c$id$orig_h] = t1;
		replycounterIn10MinsTable[c$id$orig_h] = 1;
		if ( code == 404 ){_400counterIn10MinsTable[c$id$orig_h]=1;}
		else{_400counterIn10MinsTable[c$id$orig_h]=0;}
		
		urlsetIn10MinsTable[c$id$orig_h] = b;
		add urlsetIn10MinsTable[c$id$orig_h][c$http$uri];
	}
	
	if (maxtimeTable[c$id$orig_h] - mintimeTable[c$id$orig_h] > 10mins)
	{
		if(_400counterIn10MinsTable[c$id$orig_h]>2)
			if(_400counterIn10MinsTable[c$id$orig_h]/replycounterIn10MinsTable[c$id$orig_h]>0.2)
				if(|urlsetIn10MinsTable[c$id$orig_h]|/_400counterIn10MinsTable[c$id$orig_h]>0.5)
				{
					print fmt("%s is a scanner with %d scan attemps on %d urls",c$id$orig_h,_400counterIn10MinsTable[c$id$orig_h],|urlsetIn10MinsTable[c$id$orig_h]|);
					mintimeTable[c$id$orig_h]=maxtimeTable[c$id$orig_h];
					replycounterIn10MinsTable[c$id$orig_h]=0;
					_400counterIn10MinsTable[c$id$orig_h]=0;
					urlsetIn10MinsTable[c$id$orig_h]=d;
				}
	}
}


event zeek_done()
{
}
