<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

global $modulenow;
if ( 'welcome' == $modulenow ) {
	return; // no module loaded
}
?>
</div>
<?php
settings_fields( "secupress_{$modulenow}_settings" );
?>
</form>
<?php
unset( $class_hidden );