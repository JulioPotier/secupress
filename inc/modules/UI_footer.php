<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

global $modulenow;
if ( 'welcome' == $modulenow ) {
	return; // no module loaded
}
?>
</div>
<?php
$class_hidden = secupress_is_module_active( $modulenow ) ? ' hidden' : '';
secupress_submit_button( 'primary large' . $class_hidden);
settings_fields( "secupress_{$modulenow}_settings" );
?>
</form>
<?php
unset( $class_hidden );