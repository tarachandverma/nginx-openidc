#ifndef MATCH_LIST_H_
#define MATCH_LIST_H_

	typedef struct mlx_match_event{
		time_t start;
		time_t end;
	}mlx_match_event;

	typedef struct mlx_match_header{
		char* name;
		char* value;
		char* delimAnd;
		int negate;
		int isRegex;
	}mlx_match_header;

	typedef struct mlx_match_ip{
		char* ip;
		int negate;
		int isRegex;
	}mlx_match_ip;

	typedef struct mlx_match_path{
		char* path;
		int negate;
	}mlx_match_path;
	
	typedef struct mlx_match_env{
		char* name;
		char* value;
		int negate;
		int isRegex;
	}mlx_match_env;
	
	typedef struct mlx_ml_match{
		char* host;
		int cascade;		
		mlx_match_path*	path;
		mlx_match_ip* ip;
		array_header* headerList;
		mlx_match_event* event;
	}mlx_ml_match;
	
	typedef struct mlx_matchlist{
		char* name;
		array_header* matches;
	}mlx_matchlist;
	
	mlx_match_event* ml_newMatchEventObj(pool*p);
	mlx_match_ip*ml_newMatchIpObj(pool*p);
	mlx_match_path*ml_newMatchPathObj(pool*p);
	mlx_match_header* ml_newMatchHeaderObj(pool* p);
	mlx_match_env* ml_newMatchEnvObj(pool* p);
	mlx_ml_match* ml_newMatchListMatchObj(pool* p);
//	mlx_match_header* ml_newMatchHeaderObjExt(pool* p,char*name,char*value,char* delimAnd,char* negate,char* isregex);
	int ml_isSubsetFound(pool*p,array_header* subset, array_header* set,int isRegex);
	int ml_isNegateSubsetFound(pool*p,array_header* subset, array_header* set, int isRegex);
	int matchList_isMatched(pool*p,char* regex, char* value, int isRegex);
	int matchList_isHostMatched(pool*p, char* matchHost, apr_table_t *headers_in);
	void ml_printMatchList(pool* p, array_header* arr);
#endif /*MATCH_LIST_H_*/

