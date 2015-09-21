<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

secupress_admin_heading( __( 'Modules', 'secupress' ) );

$modules = secupress_get_modules();
?>
<h2 class="nav-tab-wrapper hide-if-no-js">
	<?php
	foreach ( $modules as $key => $module ) {
		$active_class = $modulenow === $key          ? ' nav-tab-active'    : '';
		$icon         = isset( $module['dashicon'] ) ?  $module['dashicon'] : 'admin-generic';
		?>
		<a href="<?php echo secupress_admin_url( 'modules', $key ); ?>" class="nav-tab<?php echo $active_class; ?> active_module" style="outline: 0px;">
			<span class="dashicons dashicons-<?php echo $icon; ?>"></span> <?php echo $module['title']; ?>
		</a>
		<?php
	}
	?>
</h2>