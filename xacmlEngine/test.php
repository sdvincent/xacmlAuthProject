<?php


//namespace Xacmlphp;

//require_once __DIR__ . '/vendor/autoload.php';
require_once('Enforcer.php');
require_once('Decider.php');
require_once('Match.php');
require_once('Target.php');
require_once('Rule.php');
require_once('DenyOverrides.php');
require_once('Policy.php');
require_once('Subject.php');
require_once('Resource.php');
require_once('AllowOverrides.php');
require_once('Attribute.php');
require_once('PolicySet.php');
require_once('Action.php');
require_once('StringEqual.php'); 
require_once('Operation.php');



$user = $argv[1];
$action = $argv[2]

/*
Need to figure out how to make custom policies here
*/


$enforcer = new Enforcer;

$decider = new Decider();
$enforcer->setDecider($decider);

// Create some Matches
$match1 = new Match('StringEqual', 'property1', 'TestMatch1', 'test');
$match2 = new Match('StringEqual', 'property1', 'TestMatch2', 'test');

// Create a Target container for our Matches
$target = new Target();
$target->addMatches(array($match1, $match2));

// Make a new Rule and add the Target to it
$rule1 = new Rule();
$rule1->setTarget($target)
    ->setId('TestRule')
    ->setEffect('Permit')
    ->setDescription(
        'Test to see if there is an attribute on the subject'
        .'that exactly matches the word "test"'
    )
    ->setAlgorithm(new DenyOverrides());

// Make two new policies and add the Rule to it (with our Match)
$policy1 = new Policy();
$policy1->setAlgorithm('AllowOverrides')->setId('Policy1')->addRule($rule1);
$policy2 = new Policy();
$policy2->setAlgorithm('DenyOverrides')->setId('Policy2')->addRule($rule1);

// Create the subject with its own Attribute
$subject = new Subject();
$subject->addAttribute(
    new Attribute('property1', 'test')
);

// Link the Policies to the Resource
$resource = new Resource();
$resource
    ->addPolicy($policy1)
    ->addPolicy($policy2);


$environment = null;
$action = new Action();

$result = $enforcer->isAuthorized($subject, $resource, $action);
/**
 * The Subject does have a property that's equal to "test" on the "property1"
 * attribute, but the default Operation is to "fail closed". The other Match,
 * for "test1234" failed and DenyOverrides wins so the return is false.
 */

echo var_export($result, true);
return var_export($result, true);

?>
print $argv[0]."\n";
print $argv[0]."\n";