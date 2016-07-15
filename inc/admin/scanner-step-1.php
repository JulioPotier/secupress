<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );
?>
<div class="secupress-step-content-header secupress-flex secupress-flex-spaced">

	<?php
	//// TODO: create a function that return true/false to check no scans since prev version

	$is_there_something_new = false;

	$page_title = $is_there_something_new ? sprintf( __( 'There’re new exciting things in %s! You’ll need to re-scan your website', 'secupress' ), SECUPRESS_PLUGIN_NAME ) : __( 'List of security points to analyze', 'secupress' );

	if ( $is_there_something_new ) {
		$main_button =
		'<button class="secupress-button secupress-button-primary button-secupress-scan shadow" type="button" data-nonce="' . esc_attr( wp_create_nonce( 'secupress-update-oneclick-scan-date' ) ) . '">
			<span class="icon" aria-hidden="true">
				<i class="icon-radar"></i>
			</span>
			<span class="text">' . esc_html__( 'Re-scan website', 'secupress' ) . '</span>
		</button>';
	} else {
		$main_button =
		'<a href="' . secupress_admin_url( 'scanners' ) . '&step=2" class="secupress-button secupress-button-tertiary shadow">
			<span class="icon">
				<i class="icon-wrench" aria-hidden="true"></i>
			</span>
			<span class="text">' . esc_html__( 'Next step', 'secupress') . '</span>
		</a>';
	}
	?>

	<p class="secupress-step-title"><?php echo $page_title; ?></p>
	<p>
		<?php echo $main_button; ?>
	</p>
</div>

<div id="secupress-tests" class="secupress-tests">

	<?php
	if ( $is_there_something_new ) {
		//// TODO: a
		//// * function to list new modules
		//// * an invisible button to launch scans at One Click Scan (first or not)
	?>
	<div class="secupress-scans-group secupress-group-new">
		<div class="secupress-sg-header secupress-flex secupress-flex-spaced">

			<div class="secupress-sgh-name">
				<i class="icon-secupress-simple" aria-hidden="true"></i>
				<p class="secupress-sgh-title"><?php printf( esc_html__( '%sNew Items', 'secupress' ), ( SECUPRESS_PLUGIN_NAME === 'SecuPress' ? SECUPRESS_PLUGIN_NAME . ' ' .SECUPRESS_VERSION . ' ' : '' ) ); ?></p>
				<p class="secupress-sgh-description"><?php _e( 'The last added scans of the last release of the awesomeness', 'secupress' ); ?></p>
			</div>

			<div class="secupress-sgh-actions secupress-flex">
				<button class="secupress-vnormal hide-if-no-js dont-trigger-hide trigger-hide-first" type="button" data-trigger="slidetoggle" data-target="secupress-group-content-new">
					<i class="icon-angle-up" aria-hidden="true"></i>
					<span class="screen-reader-text">Show/hide panel</span>
				</button>
			</div>

		</div><!-- .secupress-sg-header -->

		<div id="secupress-group-content-new" class="secupress-sg-content">

			<div class="secupress-item-all secupress-item-[_ITEM_SLUG_] type-all status-all type-wordpress status-new not-fixable no-fix-status" id="[_ITEM_SLUG_]">
				<div class="secupress-flex">

					<p class="secupress-item-status">
						<span class="secupress-label">New</span>
					</p>

					<p class="secupress-item-title">Check if your login page is protected by double authentication or something like that (may be a custom script).</p>

					<p class="secupress-row-actions">
						<!--
							Things changed:
							* data-trigger added
							* data-target instead of data-test
							* data-target === .secupress-item-details' ID
						-->
						<button data-trigger="slidetoggle" data-target="details-[_ITEM_SLUG_]" class="secupress-details link-like hide-if-no-js" type="button">
							<span aria-hidden="true" class="icon">
								<i class="icon-info-disk"></i>
							</span>
							<span class="text">Learn more</span>
						</button>
					</p>
				</div>

				<div class="secupress-item-details hide-if-js" id="details-[_ITEM_SLUG_]">
					<div class="secupress-flex">
						<span class="secupress-details-icon">
							<i class="icon-i" aria-hidden="true"></i>
						</span>
						<p class="details-content">The login vector is often use in web attacks, every hour, your website is targeted by random bots whom try to log in your site. Adding another layer of login can improve the security.</p>
						<span class="secupress-placeholder"></span>
					</div>
				</div>

			</div><!-- .secupress-item-all -->

			<div class="secupress-item-all secupress-item-Easy_Login type-all status-all type-wordpress status-new not-fixable no-fix-status alternate-1" id="Easy_Login">

				<div class="secupress-flex">

					<p class="secupress-item-status">
						<span class="secupress-label">New</span>
					</p>

					<p class="secupress-item-title">Check if your login page is protected by double authentication or something like that (may be a custom script).</p>

					<p class="secupress-row-actions">
						<!--
							Things changed:
							* data-trigger added
							* data-target instead of data-test
							* data-target === .secupress-item-details' ID
						-->
						<button data-trigger="slidetoggle" data-target="details-Easy_Login" class="secupress-details link-like hide-if-no-js" type="button">
							<span aria-hidden="true" class="icon">
								<i class="icon-info-disk"></i>
							</span>
							<span class="text">Learn more</span>
						</button>
					</p>
				</div><!-- .secupress-flex -->

				<div class="secupress-item-details hide-if-js" id="details-Easy_Login">
					<div class="secupress-flex">
						<span class="secupress-details-icon">
							<i class="icon-i" aria-hidden="true"></i>
						</span>
						<p class="details-content">The login vector is often use in web attacks, every hour, your website is targeted by random bots whom try to log in your site. Adding another layer of login can improve the security.</p>
						<span class="secupress-placeholder"></span>
					</div>
				</div>

			</div><!-- .secupress-item-all -->

			<div class="secupress-item-all secupress-item-Easy_Login type-all status-all type-wordpress status-new not-fixable no-fix-status alternate-1" id="Easy_Login">

				<div class="secupress-flex">

					<p class="secupress-item-status">
						<span class="secupress-label">New</span>
					</p>

					<p class="secupress-item-title">Check if your login page is protected by double authentication or something like that (may be a custom script).</p>

					<p class="secupress-row-actions">
						<!--
							Things changed:
							* data-trigger added
							* data-target instead of data-test
							* data-target === .secupress-item-details' ID
						-->
						<button data-trigger="slidetoggle" data-target="details-Easy_Login" class="secupress-details link-like hide-if-no-js" type="button">
							<span aria-hidden="true" class="icon">
								<i class="icon-info-disk"></i>
							</span>
							<span class="text">Learn more</span>
						</button>
					</p>
				</div><!-- .secupress-flex -->

				<div class="secupress-item-details hide-if-js" id="details-Easy_Login">
					<div class="secupress-flex">
						<span class="secupress-details-icon">
							<i class="icon-i" aria-hidden="true"></i>
						</span>
						<p class="details-content">The login vector is often use in web attacks, every hour, your website is targeted by random bots whom try to log in your site. Adding another layer of login can improve the security.</p>
						<span class="secupress-placeholder"></span>
					</div>
				</div>

			</div><!-- .secupress-item-all -->

		</div><!-- .secupress-sg-content -->
	</div><!-- .secupress-scans-group -->
	<?php } // is something new in that version ?>

	<div class="secupress-scans-group secupress-group-[_GROUP_SLUG_]">
		<div class="secupress-sg-header secupress-flex secupress-flex-spaced">

			<div class="secupress-sgh-name">
				<i class="icon-user-login" aria-hidden="true"></i>
				<p class="secupress-sgh-title">User &amp; Login</p>
				<p class="secupress-sgh-description">Protect you users</p>
			</div>

			<div class="secupress-sgh-actions secupress-flex">
				<a href="#[_SECUPRESS_MODULE_LINK_]" target="_blank" class="secupress-link-icon secupress-vcenter">
					<span class="icon"><i class="icon-cog" aria-hidden="true"></i></span>
					<span class="text">Go to module settings</span>
				</a>
				<button class="secupress-vnormal hide-if-no-js dont-trigger-hide trigger-hide-first" type="button" data-trigger="slidetoggle" data-target="secupress-group-content-[_GROUP_SLUG_]">
					<i class="icon-angle-up" aria-hidden="true"></i>
					<span class="screen-reader-text">Show/hide panel</span>
				</button>
			</div>

		</div><!-- .secupress-sg-header -->

		<div id="secupress-group-content-[_GROUP_SLUG_]" class="secupress-sg-content">

			<div class="secupress-item-all secupress-item-[_ITEM_SLUG_] type-all status-all type-wordpress status-good not-fixable no-fix-status" id="[_ITEM_SLUG_]">
				<div class="secupress-flex">

					<p class="secupress-item-status">
						<span class="secupress-label">Good</span>
					</p>

					<p class="secupress-item-title">Check if your login page is protected by double authentication or something like that (may be a custom script).</p>

					<p class="secupress-row-actions">
						<!--
							Things changed:
							* data-trigger added
							* data-target instead of data-test
							* data-target === .secupress-item-details' ID
						-->
						<button data-trigger="slidetoggle" data-target="details-[_ITEM_SLUG_]" class="secupress-details link-like hide-if-no-js" type="button">
							<span aria-hidden="true" class="icon">
								<i class="icon-info-disk"></i>
							</span>
							<span class="text">Learn more</span>
						</button>
					</p>
				</div>

				<div class="secupress-item-details hide-if-js" id="details-[_ITEM_SLUG_]">
					<div class="secupress-flex">
						<span class="secupress-details-icon">
							<i class="icon-i" aria-hidden="true"></i>
						</span>
						<p class="details-content">The login vector is often use in web attacks, every hour, your website is targeted by random bots whom try to log in your site. Adding another layer of login can improve the security.</p>
						<span class="secupress-placeholder"></span>
					</div>
				</div>

			</div><!-- .secupress-item-all -->

			<div class="secupress-item-all secupress-item-Easy_Login type-all status-all type-wordpress status-warning not-fixable no-fix-status alternate-1" id="Easy_Login">

				<div class="secupress-flex">

					<p class="secupress-item-status">
						<span class="secupress-label">Warning</span>
					</p>

					<p class="secupress-item-title">Check if your login page is protected by double authentication or something like that (may be a custom script).</p>

					<p class="secupress-row-actions">
						<!--
							Things changed:
							* data-trigger added
							* data-target instead of data-test
							* data-target === .secupress-item-details' ID
						-->
						<button data-trigger="slidetoggle" data-target="details-Easy_Login" class="secupress-details link-like hide-if-no-js" type="button">
							<span aria-hidden="true" class="icon">
								<i class="icon-info-disk"></i>
							</span>
							<span class="text">Learn more</span>
						</button>
					</p>
				</div><!-- .secupress-flex -->

				<div class="secupress-item-details hide-if-js" id="details-Easy_Login">
					<div class="secupress-flex">
						<span class="secupress-details-icon">
							<i class="icon-i" aria-hidden="true"></i>
						</span>
						<p class="details-content">The login vector is often use in web attacks, every hour, your website is targeted by random bots whom try to log in your site. Adding another layer of login can improve the security.</p>
						<span class="secupress-placeholder"></span>
					</div>
				</div>

			</div><!-- .secupress-item-all -->

			<div class="secupress-item-all secupress-item-Easy_Login type-all status-all type-wordpress status-bad not-fixable no-fix-status alternate-1" id="Easy_Login">

				<div class="secupress-flex">

					<p class="secupress-item-status">
						<span class="secupress-label">Bad</span>
					</p>

					<p class="secupress-item-title">Check if your login page is protected by double authentication or something like that (may be a custom script).</p>

					<p class="secupress-row-actions">
						<!--
							Things changed:
							* data-trigger added
							* data-target instead of data-test
							* data-target === .secupress-item-details' ID
						-->
						<button data-trigger="slidetoggle" data-target="details-Easy_Login" class="secupress-details link-like hide-if-no-js" type="button">
							<span aria-hidden="true" class="icon">
								<i class="icon-info-disk"></i>
							</span>
							<span class="text">Learn more</span>
						</button>
					</p>
				</div><!-- .secupress-flex -->

				<div class="secupress-item-details hide-if-js" id="details-Easy_Login">
					<div class="secupress-flex">
						<span class="secupress-details-icon">
							<i class="icon-i" aria-hidden="true"></i>
						</span>
						<p class="details-content">The login vector is often use in web attacks, every hour, your website is targeted by random bots whom try to log in your site. Adding another layer of login can improve the security.</p>
						<span class="secupress-placeholder"></span>
					</div>
				</div>

			</div><!-- .secupress-item-all -->

		</div><!-- .secupress-sg-content -->
	</div><!-- .secupress-scans-group -->

</div><!-- .secupress-tests -->

<div class="secupress-step-content-footer secupress-flex secupress-flex-top secupress-flex-spaced">
	<?php
		$export_pdf_btn = '<span class="icon">
				<i class="icon-file-pdf-o" aria-hidden="true"></i>
			</span>
			<span class="text">
				' . esc_html__( 'Export as PDF', 'secupress' ) . '
			</span>';
	?>
	<p>
	<?php
		if ( !secupress_is_pro() ) {
	?>
		<button type="button" title="<?php esc_attr__( 'Export this report as PDF file.', 'secupress' ); ?>" class="secupress-button shadow">
			<?php echo $export_pdf_btn; ?>
		</button>
	<?php
		} else {
	?>
		<a href="<?php echo esc_url( secupress_admin_url( 'get_pro' ) ) ?>" type="button" title="<?php echo $get_pdf_title; ?>" target="_blank" class="secupress-button disabled shadow">
			<?php echo $export_pdf_btn; ?>
		</a>
		<br>
		<span class="secupress-get-pro-version">
			<?php printf( __( 'Available in <a href="%s">Pro Version</a>', 'secupress' ), esc_url( secupress_admin_url( 'get_pro' ) ) ); ?>
		</span>
	<?php
		}
	?>
	</p>
	<p>
		<?php echo $main_button; ?>
	</p>
</div>