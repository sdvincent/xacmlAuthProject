<?php

//namespace Xacmlphp;

/**
 * According to "Deny Overrides" if any policy in the set
 * fails, return DENY
 */
class DenyOverrides
{
    //\Xacmlphp\Policy $policy = null
    public function evaluate(array $results,  $policy = null)
    {
        return (!in_array(false, $results));
    }
}
