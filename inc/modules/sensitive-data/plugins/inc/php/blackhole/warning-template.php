<?php
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

?><!DOCTYPE html>
<html <?php language_attributes(); ?>>
	<head>
		<meta charset="<?php echo esc_attr( strtolower( get_bloginfo( 'charset' ) ) ); ?>" />
		<title><?php esc_html_e( 'STOP', 'secupress' ); ?></title>
		<meta content="noindex,nofollow" name="robots" />
		<meta content="initial-scale=1.0" name="viewport" />
	</head>
	<body>
		<p><?php
		printf(
			/** Translators: 1 is a file name, 2 is a "click here" link. */
			__( 'The aim of this page is to catch robots that don\'t respect the rules set in the %1$s file. <strong>Don\'t %2$s or you will be banned from this site.</strong>', 'secupress' ),
			'<code>robots.txt</code>',
			'<a href="' . esc_url( admin_url( 'admin-post.php?action=secupress-ban-me-please' ) ) . '">' . __( 'click this link', 'secupress' ) . '</a>'
		);
		?></p>
	</body>
</html><?php
die();
