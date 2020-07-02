<?php

namespace Drupal\ggroup_role_mapper\Access;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\ggroup\GroupHierarchyManager;
use Drupal\group\Access\GroupPermissionCalculatorBase;
use Drupal\group\Access\RefinableCalculatedGroupPermissions;
use Drupal\group\Access\CalculatedGroupPermissionsItem;
use Drupal\group\Access\CalculatedGroupPermissionsItemInterface;
use Drupal\group\Entity\Group;
use Drupal\group\Entity\GroupContentType;
use Drupal\group\Entity\GroupInterface;
use Drupal\group\GroupMembership;
use Drupal\group\GroupMembershipLoader;
use Drupal\ggroup_role_mapper\GroupRoleInheritanceInterface;

/**
 * Calculates group permissions for an account.
 */
class InheritGroupPermissionCalculator extends GroupPermissionCalculatorBase {

  /**
   * The group hierarchy manager.
   *
   * @var \Drupal\ggroup\GroupHierarchyManager
   */
  protected $hierarchyManager;

  /**
   * The entity type manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected $entityTypeManager;

  /**
   * The group membership loader.
   *
   * @var \Drupal\group\GroupMembershipLoader
   */
  protected $membershipLoader;

  /**
   * The group role inheritance manager.
   *
   * @var \Drupal\ggroup_role_mapper\GroupRoleInheritanceInterface
   */
  protected $groupRoleInheritanceManager;

  /**
   * Static cache for all group memberships per user.
   *
   * A nested array with all group memberships keyed by user ID.
   *
   * @var \Drupal\group\GroupMembership[][]
   */
  protected $userMemberships = [];

  /**
   * Static cache for all inherited group roles by user.
   *
   * A nested array with all inherited roles keyed by user ID and group ID.
   *
   * @var array
   */
  protected $mappedRoles = [];

  /**
   * Constructs a InheritGroupPermissionCalculator object.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager.
   * @param \Drupal\ggroup\GroupHierarchyManager $hierarchy_manager
   *   The group hierarchy manager.
   * @param \Drupal\group\GroupMembershipLoader $membership_loader
   *   The group membership loader.
   * @param \Drupal\ggroup_role_mapper\GroupRoleInheritanceInterface $group_role_inheritance_manager
   *   The group membership loader.
   */
  public function __construct(EntityTypeManagerInterface $entity_type_manager, GroupHierarchyManager $hierarchy_manager, GroupMembershipLoader $membership_loader, GroupRoleInheritanceInterface $group_role_inheritance_manager) {
    $this->entityTypeManager = $entity_type_manager;
    $this->hierarchyManager = $hierarchy_manager;
    $this->membershipLoader = $membership_loader;
    $this->groupRoleInheritanceManager = $group_role_inheritance_manager;
  }

  /**
   * Getter for mapped roles.
   *
   * @param string $account_id
   *   Account id.
   * @param string|null $group_id
   *   Group id.
   *
   * @return array
   *   Mapped roles, defaults to empty array.
   */
  public function getMappedRoles($account_id, $group_id = NULL) {
    if (!empty($group_id)) {
      return $this->mappedRoles[$account_id][$group_id] ?? [];
    }
    return $this->mappedRoles[$account_id] ?? [];
  }

  /**
   * Checker for mapped roles.
   *
   * @param string $account_id
   *   Account id.
   * @param string|null $group_id
   *   Group id.
   *
   * @return bool
   *   TRUE if there are mapped roles
   *   for given account id (optionally group id).
   */
  public function hasMappedRoles($account_id, $group_id = NULL) {
    return !empty($this->getMappedRoles($account_id, $group_id));
  }

  /**
   * Get all (inherited) group roles a user account inherits for a group.
   *
   * Check if the account is a direct member of any subgroups/supergroups of
   * the group. For each subgroup/supergroup, we check which roles we are
   * allowed to map. The result contains a list of all roles the user has have
   * inherited from 1 or more subgroups or supergroups.
   *
   * @param \Drupal\Core\Session\AccountInterface $account
   *   An account to map only the roles for a specific user.
   *
   * @return RefinableCalculatedGroupPermissions An array of group roles inherited for the given group.
   *   An array of group roles inherited for the given group.
   * @throws \Drupal\Component\Plugin\Exception\InvalidPluginDefinitionException
   * @throws \Drupal\Component\Plugin\Exception\PluginNotFoundException
   */
  public function calculateMemberPermissions(AccountInterface $account) {
    $calculated_permissions = new RefinableCalculatedGroupPermissions();
    $calculated_permissions->addCacheContexts(['user']);

    $user = $this->entityTypeManager->getStorage('user')->load($account->id());
    $calculated_permissions->addCacheableDependency($user);

    foreach ($this->membershipLoader->loadByUser($account) as $group_membership) {
      $group = $group_membership->getGroup();
      $group_role_array = $this->getInheritedGroupRoleIdsByMembership($group_membership, $account);
       foreach ($group_role_array as $group_id => $group_roles) {
         $permission_sets = [];
         foreach ($group_roles as $group_role) {
           $permission_sets[] = $group_role->getPermissions();
           $calculated_permissions->addCacheableDependency($group_role);
         }
         $permissions = $permission_sets ? array_merge(...$permission_sets) : [];
         $item = new CalculatedGroupPermissionsItem(
           CalculatedGroupPermissionsItemInterface::SCOPE_GROUP,
           (string) $group_id,
           $permissions
         );
         $calculated_permissions->addItem($item);
         $calculated_permissions->addCacheableDependency($group);
      }
    }
    return $calculated_permissions;
  }

  /**
   * {@inheritdoc}
   */
  public function getInheritedGroupRoleIdsByMembership(GroupMembership $group_membership, AccountInterface $account) {
    $account_id = $account->id();
    $group = $group_membership->getGroup();
    $group_id = $group->id();
    $roles = array_keys($group_membership->getRoles());

    if ($this->hasMappedRoles($account_id, $group_id)) {
      return $this->getMappedRoles($account_id, $group_id);
    }

    // Statically cache the memberships of a user since this method could get
    // called a lot.
    if (empty($this->userMemberships[$account_id])) {
      $this->userMemberships[$account_id] = $this->membershipLoader->loadByUser($account);
    }

    $role_map = $this->groupRoleInheritanceManager->getAllInheritedGroupRoleIds($group);

    $mapped_role_ids = [[]];
    foreach ($this->userMemberships[$account_id] as $membership) {
      $membership_gid = $membership->getGroup()->id();

      $subgroup_ids = $this->hierarchyManager->getGroupSupergroupIds($membership_gid) + $this->hierarchyManager->getGroupSubgroupIds($membership_gid);;
      foreach ($subgroup_ids as $subgroup_id) {
        if (!empty($role_map[$subgroup_id][$group_id])) {
          $mapped_role_ids[$subgroup_id] = array_merge(isset($mapped_role_ids[$subgroup_id]) ? $mapped_role_ids[$subgroup_id] : [], array_intersect_key($role_map[$subgroup_id][$group_id], array_flip($roles)));
        }
      }
    }

    foreach ($mapped_role_ids as $group_id => $role_ids) {
      if (!empty(array_unique($role_ids))) {
        $this->mappedRoles[$account_id][$group_id] = array_merge($this->getMappedRoles($account_id, $group_id), $this->entityTypeManager->getStorage('group_role')->loadMultiple(array_unique($role_ids)));
      }
    }

    return $this->getMappedRoles($account_id);
  }

}
