import AuthContext from "@/context/AuthProvider";
import { useContext } from "react";

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error(
      "AuthContext error: AuthContext must be used within AuthProvider."
    );
  }
  return context;
};
export default useAuth;
