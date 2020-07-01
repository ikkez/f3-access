<?php

class Access extends \Prefab {

    //Constants
    const
        DENY='deny',
        ALLOW='allow';

    /** @var string Default policy */
    protected $policy=self::ALLOW;

    /** @var array */
    protected $rules=[];

    /** @var \Base */
    protected $f3;

    /**
     * Define an access rule to a route
     * @param bool $accept
     * @param string $route
     * @param string|array $subjects
     * @return self
     */
    function rule($accept,$route,$subjects='') {
        if (!is_array($subjects))
            $subjects=explode(',',$subjects);
        list($verbs,$path)=$this->parseRoute($route);
        foreach($subjects as $subject)
            foreach($verbs as $verb)
                $this->rules[$subject?:'*'][$verb][$path]=$accept;
        return $this;
    }

    /**
     * Give access to a route
     * @param string $route
     * @param string|array $subjects
     * @return self
     */
    function allow($route,$subjects='') {
        return $this->rule(TRUE,$route,$subjects);
    }

    /**
     * Deny access to a route
     * @param string $route
     * @param string|array $subjects
     * @return self
     */
    function deny($route,$subjects='') {
        return $this->rule(FALSE,$route,$subjects);
    }

    /**
     * Get/set the default policy
     * @param string $default
     * @return self|string
     */
    function policy($default=NULL) {
        if (!isset($default))
            return $this->policy;
        if (in_array($default=strtolower($default),[self::ALLOW,self::DENY]))
            $this->policy=$default;
        return $this;
    }

    /**
     * Return TRUE if the given subject (or any of the given subjects) is granted access to the given route
     * @param string|array $route
     * @param string|array $subject
     * @return bool
     */
    function granted($route,$subject='') {
        list($verbs,$uri)=is_array($route)?$route:$this->parseRoute($route);
        if (is_array($subject)) {
            foreach($subject?:[''] as $s)
                if ($this->granted([$verbs,$uri],$s))
                    return TRUE;
            return FALSE;
        }
        $verb=$verbs[0];//we shouldn't get more than one verb here
        $others=[];
        foreach ($this->rules as $sub => $verbs)
            if ($sub!=$subject && isset($verbs[$verb]))
                foreach ($verbs[$verb] as $path => $rule) {
                    if (!isset($others[$path]))
                        $others[$path]=[$sub=>$rule];
                    else
                        $others[$path][$sub]=$rule;
                }
        $specific=$this->rules[$subject][$verb] ?? [];
        $global=$this->rules['*'][$verb] ?? [];
        $rules=$specific+$global;//subject-specific rules have precedence over global rules
        //specific paths are processed first:
        $paths=[];
        foreach ($keys=array_keys($rules) as $key) {
            $path=str_replace('@','*@',$key);
            if (substr($path,-1)!='*')
                $path.='+';
            $paths[]=$path;
        }
        $vals=array_values($rules);
        array_multisort($paths,SORT_DESC,$keys,$vals);
        $rules=array_combine($keys,$vals);
        foreach($rules as $path=>$rule)
            if (preg_match('/^'.preg_replace('/@\w*/','[^\/]+',
                str_replace('\*','.*',preg_quote($path,'/'))).'$/',$uri))
                return (strpos($path,'@')!==FALSE && isset($others[$uri]))
                    ? !$this->policy==self::DENY: $rule;
        return $this->policy==self::ALLOW;
    }

    /**
     * Authorize a given subject (or a set of subjects)
     * @param string|array $subject
     * @param callable|string $ondeny
     * @return bool
     */
    function authorize($subject='',$ondeny=NULL) {
        if (!$this->granted($route=$this->f3->VERB.' '.$this->f3->PATH,$subject) &&
            (!isset($ondeny) || FALSE===$this->f3->call($ondeny,array($route,$subject)))) {
            $this->f3->error($subject?403:401);
            return FALSE;
        }
        return TRUE;
    }

    /**
     * Parse a route string
     * Possible route formats are:
     * - GET /foo
     * - GET|PUT /foo
     * - /foo
     * - * /foo
     * @param $str
     * @return array
     */
    protected function parseRoute($str) {
        $verbs=$path='';
        if (preg_match('/^\h*(\*|[|\w]*)\h*(\H+)/',$str,$m)) {
            list(,$verbs,$path)=$m;
            if ($path[0]=='@') {
                $alias=substr($path,1);
                $path=$this->f3['ALIASES'][$alias];
                if (!$verbs) {
                    $verbs=[];
                    foreach($this->f3['ROUTES'][$path]?:[] as $type=>$route) {
                        foreach ($route as $verb => $conf)
                            if ($conf[3] == $alias)
                                $verbs[]=$verb;
                    }
                    $verbs=array_unique($verbs);
                }
            }
        }
        if (!$verbs || $verbs=='*')
            $verbs=\Base::VERBS;
        if (!is_array($verbs))
            $verbs=explode('|',$verbs);
        return [$verbs,$path];
    }

    /**
     * Constructor
     * @param array $config
     */
    function __construct($config=NULL) {
        $this->f3=\Base::instance();
        if (!isset($config))
            $config=(array)$this->f3->ACCESS;
        if (isset($config['policy']))
            $this->policy($config['policy']);
        if (isset($config['rules']))
            foreach((array)$config['rules'] as $str=>$subjects) {
                foreach([self::DENY,self::ALLOW] as $k=>$policy)
                    if (stripos($str,$policy)===0)
                        $this->rule((bool)$k,substr($str,strlen($policy)),$subjects);
            }
    }

}
