<?php

//namespace Xacmlphp;

/**
 * According to "Deny Overrides" if any policy in the set
 * fails, return DENY
 */
class AllowOverrides
{
    //\Algorithm\Policy $policy 
    public function evaluate(array $results, $policy = null)
    {
        return in_array(true, $results);
    }
}
