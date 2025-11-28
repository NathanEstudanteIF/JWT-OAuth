import { DataTypes } from "sequelize";
import sequelize from "../config/database.js";
import User from "./user.js";

const RefreshToken = sequelize.define("RefreshToken", {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    token: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    expiresAt: {
        type: DataTypes.DATE,
        allowNull: false,
    },
});

RefreshToken.verifyExpiration = (token) => {
return token.expiresAt.getTime() < new Date().getTime();
};

RefreshToken.belongsTo(User, { foreignKey: "userId" });
export default RefreshToken;