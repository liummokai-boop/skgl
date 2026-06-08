# 记账客户管理系统 - Mac 桌面试用版

这是桌面单机版入口，不影响线上网页版 `https://skgl.pages.dev/`。

## 本地运行

```bash
cd desktop
npm install
npm start
```

默认管理员：

```text
手机号：13399330020
密码：123456
```

## 数据位置

本地数据库文件保存在 macOS 应用数据目录：

```text
~/Library/Application Support/记账客户管理系统/skgl-local.sqlite
```

## 打包 Mac App

```bash
cd desktop
npm run dist:mac
```

生成文件在：

```text
desktop/release/
```

第一版未做苹果开发者签名，首次打开可能需要右键“打开”，或在系统设置里允许打开。
