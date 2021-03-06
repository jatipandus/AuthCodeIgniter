        <!-- Sidebar -->
        <ul class="navbar-nav bg-gradient-primary sidebar sidebar-dark accordion" id="accordionSidebar">

            <!-- Sidebar - Brand -->
            <a class="sidebar-brand d-flex align-items-center justify-content-center" href="index.html">
                <div class="sidebar-brand-icon rotate-n-15">
                    <i class="fas fa-eye"></i>
                </div>
                <div class="sidebar-brand-text mx-3">SB Admin</div>
            </a>

            <!-- Divider -->
            <hr class="sidebar-divider">


            <?php
            $role_id = $this->session->userdata('role_id');
            $queryMenu = "Select `user_menu`.`id`, `menu` 
                          FROM `user_menu` 
                          JOIN `user_access_menu`
                          ON `user_menu`.`id` = `user_access_menu`.`menu_id`
                          WHERE `user_access_menu`.`role_id` = $role_id
                          ORDER BY `user_access_menu`.`menu_id`";
            $menu = $this->db->query($queryMenu)->result_array();

            // var_dump($menu);
            // die;

            ?>

            <!-- LOOPING MENU -->
            <?php foreach ($menu as $m) : ?>
                <div class="sidebar-heading">
                    <?= $m['menu']; ?>
                </div>

                <?php
                $menuId = $m['id'];
                $querySubMenu = "Select * 
                                     FROM `user_submenu` 
                                     WHERE `menu_id` = $menuId
                                     and `is_active` = 1";
                $subMenu = $this->db->query($querySubMenu)->result_array();

                ?>
                <?php foreach ($subMenu as $sm) :
                    if ($title == $sm['title']) { ?>

                        <li class="nav-item active">

                        <?php
                    } else {
                        ?>

                        <li class="nav-item">

                        <?php } ?>

                        <!-- Nav Item - Dashboard -->

                        <a class="nav-link" href="<?= base_url($sm['url']) ?>">
                            <i class="<?= $sm['icon'] ?>"></i>
                            <span><?= $sm['title'] ?></span>
                        </a>
                        </li>

                    <?php endforeach; ?>

                    <!-- Divider -->
                    <hr class="sidebar-divider">

                <?php endforeach; ?>

                <!-- Nav Item - Pages Collapse Menu -->
                <li class="nav-item">
                    <a class="nav-link" href="#" data-toggle="modal" data-target="#logoutModal">
                        <i class="fas fa-sign-out-alt"></i>
                        <span>Logout</span></a>
                </li>

                <!-- Divider -->
                <hr class="sidebar-divider d-none d-md-block">

                <!-- Sidebar Toggler (Sidebar) -->
                <div class="text-center d-none d-md-inline">
                    <button class="rounded-circle border-0" id="sidebarToggle"></button>
                </div>

        </ul>
        <!-- End of Sidebar -->