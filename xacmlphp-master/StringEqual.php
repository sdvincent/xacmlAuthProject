<?php

//namespace Xacmlphp\Operation;

class StringEqual
{
    public function evaluate($prop1, $prop2)
    {
        //$vals = new Operation("ass","titties"); 
        //$prop1 = $vals->getProperty1();
       // print "prop 1: ".$prop1."\n";
        //$prop2 = $vals->getProperty2();
       /// print "prop 2: ".$prop2."\n";

        return $prop1 == $prop2;
    }
}
