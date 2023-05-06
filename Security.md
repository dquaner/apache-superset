---
description: Superset 中的权限管理。
---

# Security

## Roles

Superset 的安全性问题由 Flask AppBuilder (FAB) 处理，Flask AppBuilder 是在 Flask 的基础上构建的一个应用程序开发框架，提供了认证、用户管理、权限和角色。相关阅读：[安全文档](security/security-flask-appbuilder.md)。

## Superset 提供的角色

Superset 提供了一组自己管理的角色，这些角色会随着 Superset 的版本更新保持最新。

即使 Admin 用户能够编辑其他的角色，但我们不建议改变 superset 提供的每种角色的权限（比如对角色移除或添加某种权限），因为当你执行 `superset init` 的时候（通常在切换 superset 版本时），每种角色相关的权限会被重置。

Roles   | Descripton
---     | ---
Admin   | Admin 用户拥有所有权限，包括 granting 或 revoking 其他用户的权限，以及编辑其他用户的 slices(charts?) 或 dashboards 。
Alpha   | Alpha 用户拥有所有数据源的权限，但他们无法管理其他用户的权限；并且他们只能更改属于（as an owner）他们自己的 objects ；Alpha 用户可以添加或修改自己的数据源。
Gamma   | Gamma 用户的权限有限，他们只能使用他们有权访问的数据源中的数据；他们对数据源的访问权限需要其他用户帮忙添加。目前 Gamma 用户无权新增或更改数据源，我们假设这种用户主要是内容的消费者，即使他们可以创建 slices 和 dashboards 。且 Gamma 用户在浏览 dashboards 和 slices 列表视图时，也只能看到他们有权访问的 objects 。
sql_lab | `sql_lab` 角色给用户添加 SQL Lab 访问权限。默认情况下，Admin 用户有权访问所有数据库，Alpha 用户和 Gamma 用户都需要首先被赋予某个数据库的访问权限。
Public  | 为了允许匿名用户使用某些 superset 的功能，可以使用 `PUBLIC_ROLE_LIKE` 配置属性，当给它分配一个其他角色，会把该角色的权限传递给 Public 角色。比如，当你在 `superset_config.py` 文件中设置了 `PUBLIC_ROLE_LIKE="Gamma"` 时，代表着你给 Public 角色赋予了与 Gamma 角色相同的权限。当你想让匿名用户有权查看 dashboards 时，这会是个有用的办法；另外还需要显示的授权具体数据集，也就是说手动添加 public 数据源到 Public 角色上。 

## 管理 Gamma 用户的数据源访问权限

那么如何给用户提供指定数据集上的访问权限呢？首先你要确保用户目前只被分配了 Gamma 角色，然后可以创建一个新的角色（ `Settings` -> `Security` -> `List Roles` -> 点击 `+` 图标 ）。

弹出框允许你给新的角色定义一个名字，并且在 `Permissions` 下拉框选择需要的权限。要选择你想要分配给该角色的数据源，只需要在下拉框键入你的表名（datasets）进行搜索。然后你可以向你的 Gamma 用户确认他们是否可以看到与你刚刚分配给他的表（例如，`datasource access on [database_name].[dataset_name](id:number)`）相关的 dashboards 和 slices 。

## 自定义权限

FAB 提供了非常细粒度的权限，并且允许大力度的自定义。FAB 为每个模型以及每个视图自动创建很多权限（can_add, can_delete, can_show, can_edit, …）。以此为基础，Superset 提供了更多粒度的权限，例如**访问所有数据源**。

**我们不建议修改 3 个基本角色，因为 Superset 是建立在与之相关的一组假设之上的**。不过，你可以创建自己的角色，并将它们与现有角色联合起来。

### 权限

角色由一组权限组成，并且 Superset 中有多种权限，如下：

- 模型和动作（Model & Action）：模型是指如 Dashboard，Slice，User 之类的实体。每种模型有一组固定的权限，包括 **can_edit**，**can_show**，**can_delete**，**can_list**，**can_add** 等。例如，如果想要允许一个用户对 dashboards 进行删除操作，那么你可以创建一个角色，为角色添加 Dashboard 实体上的 **can_delete** 权限，并将角色分配给该用户。

- 视图（Views）：视图是独立的网络页面，例如 Explore 视图或 SQL Lab 视图。当将视图权限分配给用户时，他们可以在菜单栏中看到相应的视图，并可以加载对应的页面。

- 数据源（Data source）：每个数据源都有独立的权限。如果一个用户没有被赋予 `all_datasource_access` 权限，那么他只能查看 Slices 或者探索他被赋予了权限的那些数据源。

- 数据库（Database）：给用户分配数据库的权限意味着允许用户访问所有此数据库内的数据源，并且允许用户在 SQL Lab 中对此数据库进行查询操作（前提是用户已被授予 SQL Lab 权限）。

### 限制数据源子集的权限

1. 我们建议给一个用户赋予 **Gamma** 角色以及有权访问特定数据源的角色。

2. 我们建议为每个权限配置创建一个各自独立的角色。例如，Finance 团队的用户可能在一些数据库和数据源上有权限，这些权限可以合并到单个角色 **Finance** 中。然后就可以分配给团队中的用户一个 **Gamma** 角色作为基础，以及一个包含了一系列数据对象权限的 **Finance** 角色。

3. 用户可以被分配多个与他们相关的角色。例如 Finance 团队的主管应该有 **Gamma**，**Finance**，以及 **Executive** 角色；其中 **Executive** 角色有权访问只开放给主管的那些数据源和 dashboards 。

4. 在 **Dashboards** 视图中，用户只能看到他们有权访问的那些仪表板。

### 行级安全性

使用 **Security** 菜单栏下的 Row Level Security 过滤器，你可以创建分配给特定表以及特定角色的过滤器。

如果你需要 Finance 团队的成员仅有权访问一张表中 `department = "finance"` 的行，你可以：

- 创建子句为 (`department = "finance"`) 的 Row Level Security 过滤器
- 然后将该子句分配给 **Finance** 角色以及相应的表

The **clause** field, which can contain arbitrary text, is then added to the generated
SQL statement’s WHERE clause. So you could even do something like create a filter
for the last 30 days and apply it to a specific role, with a clause
like `date_field > DATE_SUB(NOW(), INTERVAL 30 DAY)`. It can also support
multiple conditions: `client_id = 6` AND `advertiser="foo"`, etc.

All relevant Row level security filters will be combined together (under the hood,
the different SQL clauses are combined using AND statements). This means it's
possible to create a situation where two roles conflict in such a way as to limit a table subset to empty.

For example, the filters `client_id=4` and `client_id=5`, applied to a role,
will result in users of that role having `client_id=4` AND `client_id=5`
added to their query, which can never be true.

## 内容安全策略 (CSP)

Superset 使用 [Talisman](https://pypi.org/project/flask-talisman/) 扩展来启用一个
[Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) 的实现，一个额外的安全层，有助于检测和减轻某些类型的攻击，包括跨站点脚本 (XSS) 和数据注入攻击。

通过指定浏览器应该认为是可执行脚本的有效来源的域，CSP 使服务器管理员能够减少或消除可能发生 XSS 的途径。然后，兼容 CSP 的浏览器将只执行从这些允许的域接收的源文件中加载的脚本，忽略所有其他脚本（包括内联脚本和事件处理 HTML 属性）。

策略是使用一系列策略指令来描述的，每个策略指令都描述了针对特定资源类型或策略区域的策略。你可以在[这里](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)查看可能的指令。

部署 Superset 时，正确配置内容安全策略以防止多种类型的攻击非常重要。Superset 在 `config.py` 中提供了两个可用于部署 CSP 的变量：

- `TALISMAN_ENABLED` 默认为 `False` ；如果要实现一个 CSP ，将该属性设置为 `True` 。
- `TALISMAN_CONFIG` 定义了实际的策略以及需要传递给 Talisman 的其他参数（*查看下面的示例*）。

Production 模式下，Superset 将在启动时检查 CSP 是否存在，如果没有找到，它将发出安全风险警告。对于在 Superset 之外使用其他软件定义 CSP 策略的环境，管理员可以使用 `config.py` 中的 `CONTENT_SECURITY_POLICY_WARNING` 禁用此警告。

### CSP 需求

* Superset needs both the `'unsafe-eval'` and `'unsafe-inline'` CSP keywords in order to operate.

  ```
  default-src 'self' 'unsafe-eval' 'unsafe-inline'
  ```

* Some dashboards load images using data URIs and require `data:` in their `img-src`

  ```
  img-src 'self' data:
  ```

* MapBox charts use workers and need to connect to MapBox servers in addition to the Superset origin

  ```
  worker-src 'self' blob:
  connect-src 'self' https://api.mapbox.com https://events.mapbox.com
  ```

This is a basic example `TALISMAN_CONFIG` that implements the above requirements, uses `'self'` to
limit content to the same origin as the Superset server, and disallows outdated HTML elements by
setting `object-src` to `'none'`.

```python
TALISMAN_CONFIG = {
    "content_security_policy": {
        "default-src": ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        "img-src": ["'self'", "data:"],
        "worker-src": ["'self'", "blob:"],
        "connect-src": ["'self'", "https://api.mapbox.com", "https://events.mapbox.com"],
        "object-src": "'none'",
    }
}
```

### 其他 Talisman 安全注意事项

Setting `TALISMAN_ENABLED = True` will invoke Talisman's protection with its default arguments,
of which `content_security_policy` is only one. Those can be found in the
[Talisman documentation](https://pypi.org/project/flask-talisman/) under *Options*.
These generally improve security, but administrators should be aware of their existence.

In particular, the default option of `force_https = True` may break Superset's Alerts & Reports
if workers are configured to access charts via a `WEBDRIVER_BASEURL` beginning
with `http://`.  As long as a Superset deployment enforces https upstream, e.g.,
through a loader balancer or application gateway, it should be acceptable to set this
option to `False`, like this:

```python
TALISMAN_CONFIG = {
    "force_https": False,
    "content_security_policy": { ...
```

## 报告安全漏洞

Apache 软件基金会在消除其软件项目中的安全问题方面采取了严格的立场。Apache Superset 对与它的特性和功能相关的问题非常敏感。

如果你担心 Superset 的安全性，或者发现了漏洞或潜在威胁，请不要犹豫，通过发送邮件到 `security@apache.org` 与 Apache 安全团队取得联系。在邮件中，请在问题或潜在威胁的描述中指明项目名称为 Superset ，并提出重现问题的办法。安全团队和 Superset 社区将在评估和分析调查结果之后回复您。

请首先通过邮件报告安全问题，然后再在公共领域进行披露
。ASF 安全团队维护了一个页面，其中描述了漏洞和潜在的威胁将被如何处理，查看他们的网页了解更多细节。